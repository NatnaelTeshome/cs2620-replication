import os
import json
import pickle
import pytest
from datetime import datetime
from unittest.mock import patch, ANY

from storage import PersistentLog, StateMachine

# === Fixtures ===

@pytest.fixture
def temp_data_dir(tmp_path):
    """Provides a temporary data directory for tests."""
    return tmp_path / "test_data"

@pytest.fixture
def node_id():
    """Provides a consistent node ID for tests."""
    return "node1"

@pytest.fixture
def persistent_log(temp_data_dir, node_id):
    """Provides a PersistentLog instance using the temporary directory."""
    log = PersistentLog(node_id, data_dir=str(temp_data_dir))
    # Ensure cleanup of files if a test fails mid-operation, though tmp_path handles dir cleanup
    yield log
    # Teardown logic can go here if needed, but tmp_path handles the directory

@pytest.fixture
def state_machine(temp_data_dir, node_id):
    """Provides a StateMachine instance using the temporary directory."""
    # Use a small snapshot interval for testing snapshot triggering
    sm = StateMachine(node_id, data_dir=str(temp_data_dir), snapshot_interval=3)
    yield sm
    # Teardown logic if needed

# === PersistentLog Tests ===

class TestPersistentLog:
    def test_init_new(self, temp_data_dir, node_id):
        """Test initialization when no prior data exists."""
        log_dir = temp_data_dir / node_id
        assert not log_dir.exists()

        log = PersistentLog(node_id, data_dir=str(temp_data_dir))

        assert log_dir.is_dir()
        assert (log_dir / "metadata.json").exists()
        assert log.node_id == node_id
        assert log.log == []
        assert log.metadata == {
            "current_term": 0,
            "voted_for": None,
            "commit_index": 0,
            "last_applied": 0,
        }
        # Verify metadata file content
        with open(log.metadata_file, "r") as f:
            meta_on_disk = json.load(f)
        assert meta_on_disk == log.metadata

    def test_init_existing(self, temp_data_dir, node_id):
        """Test initialization when data files already exist."""
        log_dir = temp_data_dir / node_id
        log_dir.mkdir(parents=True)

        # Pre-populate metadata
        existing_meta = {
            "current_term": 5,
            "voted_for": "node2",
            "commit_index": 10,
            "last_applied": 8,
        }
        with open(log_dir / "metadata.json", "w") as f:
            json.dump(existing_meta, f)

        # Pre-populate log
        existing_log_entries = [
            {"term": 1, "command": "cmd1"},
            {"term": 5, "command": "cmd2"},
        ]
        with open(log_dir / "log", "wb") as f:
            pickle.dump(existing_log_entries, f)

        log = PersistentLog(node_id, data_dir=str(temp_data_dir))

        assert log.metadata == existing_meta
        assert log.log == existing_log_entries

    def test_metadata_get_set(self, persistent_log, temp_data_dir, node_id):
        """Test getters and setters for metadata, ensuring persistence."""
        # Term
        assert persistent_log.get_current_term() == 0
        persistent_log.set_current_term(10)
        assert persistent_log.get_current_term() == 10

        # Voted For
        assert persistent_log.get_voted_for() is None
        persistent_log.set_voted_for("node3")
        assert persistent_log.get_voted_for() == "node3"

        # Commit Index
        assert persistent_log.get_commit_index() == 0
        persistent_log.set_commit_index(5)
        assert persistent_log.get_commit_index() == 5

        # Last Applied
        assert persistent_log.get_last_applied() == 0
        persistent_log.set_last_applied(3)
        assert persistent_log.get_last_applied() == 3

        # Verify persistence by creating a new instance
        log2 = PersistentLog(node_id, data_dir=str(temp_data_dir))
        assert log2.get_current_term() == 10
        assert log2.get_voted_for() == "node3"
        assert log2.get_commit_index() == 5
        assert log2.get_last_applied() == 3
        assert log2.metadata == persistent_log.metadata

    def test_append_entries_new(self, persistent_log, temp_data_dir, node_id):
        """Test appending entries to an empty log."""
        entries = [{"term": 1, "cmd": "A"}, {"term": 1, "cmd": "B"}]
        success, last_index = persistent_log.append_entries(entries, 0)

        assert success is True
        assert last_index == 1
        assert persistent_log.log == entries
        assert persistent_log.get_last_log_index() == 1
        assert persistent_log.get_last_log_term() == 1

        # Verify persistence
        log2 = PersistentLog(node_id, data_dir=str(temp_data_dir))
        assert log2.log == entries

    def test_append_entries_overwrite(self, persistent_log, temp_data_dir, node_id):
        """Test appending entries that overwrite existing ones."""
        initial_entries = [{"term": 1, "cmd": "A"}, {"term": 1, "cmd": "B"}]
        persistent_log.append_entries(initial_entries, 0)

        new_entries = [{"term": 2, "cmd": "C"}, {"term": 2, "cmd": "D"}]
        # Append starting at index 1, overwriting {"term": 1, "cmd": "B"}
        success, last_index = persistent_log.append_entries(new_entries, 1)

        assert success is True
        assert last_index == 2
        expected_log = [{"term": 1, "cmd": "A"}, {"term": 2, "cmd": "C"}, {"term": 2, "cmd": "D"}]
        assert persistent_log.log == expected_log
        assert persistent_log.get_last_log_index() == 2
        assert persistent_log.get_last_log_term() == 2

        # Verify persistence
        log2 = PersistentLog(node_id, data_dir=str(temp_data_dir))
        assert log2.log == expected_log

    def test_append_entries_gap(self, persistent_log):
        """Test appending entries where start_index > len(log) (should just extend)."""
        initial_entries = [{"term": 1, "cmd": "A"}]
        persistent_log.append_entries(initial_entries, 0) # log = [A]

        new_entries = [{"term": 2, "cmd": "B"}]
        # Append starting at index 2, log length is 1. Should append at index 1.
        success, last_index = persistent_log.append_entries(new_entries, 2)

        assert success is True
        assert last_index == 1 # Appended at the end
        expected_log = [{"term": 1, "cmd": "A"}, {"term": 2, "cmd": "B"}]
        assert persistent_log.log == expected_log

    def test_get_entries(self, persistent_log):
        """Test retrieving entries with various indices."""
        entries = [
            {"term": 1, "cmd": "A"},
            {"term": 1, "cmd": "B"},
            {"term": 2, "cmd": "C"},
            {"term": 3, "cmd": "D"},
        ]
        persistent_log.append_entries(entries, 0)

        assert persistent_log.get_entries(0, 2) == entries[0:2]
        assert persistent_log.get_entries(1, 3) == entries[1:3]
        assert persistent_log.get_entries(2) == entries[2:] # No end index
        assert persistent_log.get_entries(0) == entries # No end index from start
        assert persistent_log.get_entries(4) == [] # Start index out of bounds
        assert persistent_log.get_entries(1, 1) == [] # Start == end
        assert persistent_log.get_entries(1, 5) == entries[1:] # End index out of bounds

    def test_get_last_log_info_empty(self, persistent_log):
        """Test getting last log info when the log is empty."""
        assert persistent_log.get_last_log_index() == -1
        assert persistent_log.get_last_log_term() == 0

    def test_get_last_log_info_non_empty(self, persistent_log):
        """Test getting last log info when the log has entries."""
        entries = [{"term": 1, "cmd": "A"}, {"term": 2, "cmd": "B"}]
        persistent_log.append_entries(entries, 0)
        assert persistent_log.get_last_log_index() == 1
        assert persistent_log.get_last_log_term() == 2


# === StateMachine Tests ===

class TestStateMachine:

    def test_init_new(self, temp_data_dir, node_id):
        """Test StateMachine initialization without existing snapshot."""
        sm_dir = temp_data_dir / node_id
        assert not sm_dir.exists()

        sm = StateMachine(node_id, data_dir=str(temp_data_dir))

        assert sm_dir.is_dir()
        assert (sm_dir / "snapshot").exists()
        assert (sm_dir / "snapshot_index").exists()
        assert sm.node_id == node_id
        assert sm.db == {
            "accounts": {},
            "id_to_message": {},
            "global_message_id": 0,
        }
        assert sm.last_snapshot_index == 0
        assert sm.commands_since_snapshot == 0

        # Verify snapshot file content
        with open(sm.snapshot_file, "rb") as f:
            snap_db = pickle.load(f)
        assert snap_db == sm.db
        with open(sm.snapshot_index_file, "r") as f:
            snap_idx = int(f.read().strip())
        assert snap_idx == 0

    def test_init_existing_snapshot(self, temp_data_dir, node_id):
        """Test StateMachine initialization with an existing snapshot."""
        sm_dir = temp_data_dir / node_id
        sm_dir.mkdir(parents=True)

        # Pre-populate snapshot
        existing_db = {
            "accounts": {"user1": {"password_hash": "hash1", "messages": [], "conversations": {}}},
            "id_to_message": {},
            "global_message_id": 5,
        }
        existing_index = 10
        with open(sm_dir / "snapshot", "wb") as f:
            pickle.dump(existing_db, f)
        with open(sm_dir / "snapshot_index", "w") as f:
            f.write(str(existing_index))

        sm = StateMachine(node_id, data_dir=str(temp_data_dir))

        assert sm.db == existing_db
        assert sm.last_snapshot_index == existing_index
        assert sm.commands_since_snapshot == 0 # Reset on load

    def test_apply_command_unknown(self, state_machine):
        """Test applying an unknown command type."""
        result = state_machine.apply_command({"type": "non_existent_command"})
        assert result == (False, "Unknown command type.")

    def test_create_account(self, state_machine):
        """Test account creation."""
        # Success
        result = state_machine.apply_command({
            "type": "create_account",
            "username": "user1",
            "password_hash": "hash1"
        }, log_index=1)
        assert result == (True, "New account 'user1' created.")
        assert "user1" in state_machine.db["accounts"]
        assert state_machine.db["accounts"]["user1"]["password_hash"] == "hash1"
        assert state_machine.db["accounts"]["user1"]["messages"] == []
        assert state_machine.db["accounts"]["user1"]["conversations"] == {}

        # Duplicate username
        result = state_machine.apply_command({
            "type": "create_account",
            "username": "user1",
            "password_hash": "hash2"
        }, log_index=2)
        assert result == (False, "Username already exists.")
        assert state_machine.db["accounts"]["user1"]["password_hash"] == "hash1" # Unchanged

    def test_check_username(self, state_machine):
        """Test username existence check."""
        state_machine.apply_command({
            "type": "create_account",
            "username": "user1",
            "password_hash": "hash1"
        })
        assert state_machine.apply_command({"type": "check_username", "username": "user1"}) == (True, "Username exists.")
        assert state_machine.apply_command({"type": "check_username", "username": "user2"}) == (False, "Username does not exist.")

    def test_login(self, state_machine):
        """Test user login functionality."""
        state_machine.apply_command({"type": "create_account", "username": "user1", "password_hash": "hash1"})
        state_machine.apply_command({"type": "create_account", "username": "user2", "password_hash": "hash2"})
        # Send an unread message to user1
        state_machine.apply_command({"type": "send_message", "from_": "user2", "to": "user1", "content": "hi"})

        # Successful login
        result = state_machine.apply_command({"type": "login", "username": "user1", "password_hash": "hash1"})
        assert result == (True, "Logged in as 'user1'. Unread messages: 1.", 1)

        # Incorrect password
        result = state_machine.apply_command({"type": "login", "username": "user1", "password_hash": "wrong_hash"})
        assert result == (False, "Incorrect password.", 0)

        # Non-existent user
        result = state_machine.apply_command({"type": "login", "username": "user3", "password_hash": "any_hash"})
        assert result == (False, "No such user.", 0)

    def test_send_message(self, state_machine):
        """Test sending messages."""
        state_machine.apply_command({"type": "create_account", "username": "sender", "password_hash": "h1"})
        state_machine.apply_command({"type": "create_account", "username": "receiver", "password_hash": "h2"})

        # Send to non-existent user
        result = state_machine.apply_command({
            "type": "send_message",
            "from_": "sender",
            "to": "non_existent",
            "content": "hello?"
        }, log_index=3)
        assert result == (False, "Recipient does not exist.")

        # Successful send
        with patch('storage.datetime') as mock_dt:
            mock_dt.now.return_value.timestamp.return_value = 1234567890
            result = state_machine.apply_command({
                "type": "send_message",
                "from_": "sender",
                "to": "receiver",
                "content": "message content"
            }, log_index=4)

        assert result[0] is True
        assert result[1] == "Message sent to 'receiver': message content"
        message_id = result[2]
        assert message_id == 1 # First message
        assert state_machine.db["global_message_id"] == 1

        # Check receiver's state
        receiver_acc = state_machine.db["accounts"]["receiver"]
        assert len(receiver_acc["messages"]) == 1
        msg = receiver_acc["messages"][0]
        assert msg["id"] == message_id
        assert msg["from_"] == "sender"
        assert msg["to"] == "receiver"
        assert msg["content"] == "message content"
        assert msg["read"] is False
        assert msg["timestamp"] == 1234567890

        # Check receiver's conversations
        assert "sender" in receiver_acc["conversations"]
        assert len(receiver_acc["conversations"]["sender"]) == 1
        assert receiver_acc["conversations"]["sender"][0] == msg

        # Check global mapping
        assert message_id in state_machine.db["id_to_message"]
        assert state_machine.db["id_to_message"][message_id] == msg

    def test_list_accounts(self, state_machine):
        """Test listing accounts with patterns and pagination."""
        # Requires logged-in user, create one
        state_machine.apply_command({"type": "create_account", "username": "lister", "password_hash": "h"})
        # Create accounts to list
        for i in range(25):
            state_machine.apply_command({"type": "create_account", f"username": f"user_{i:02d}", "password_hash": "h"})
            state_machine.apply_command({"type": "create_account", f"username": f"other_{i:02d}", "password_hash": "h"})

        # List without pattern (page 1)
        success, msg, accounts, total = state_machine.apply_command({
            "type": "list_accounts", "username": "lister", "page_size": 10, "page_num": 1
        })
        assert success is True
        assert total == 51 # 25 user_, 25 other_, 1 lister
        assert len(accounts) == 10
        assert accounts[0] == "lister"
        assert accounts[1] == "other_00"
        # ... up to other_08

        # List without pattern (page 2)
        success, msg, accounts, total = state_machine.apply_command({
            "type": "list_accounts", "username": "lister", "page_size": 10, "page_num": 2
        })
        assert success is True
        assert total == 51
        assert len(accounts) == 10
        assert accounts[0] == "other_09"
        # ... up to other_18

        # List with pattern
        success, msg, accounts, total = state_machine.apply_command({
            "type": "list_accounts", "username": "lister", "pattern": "user_1*", "page_size": 5, "page_num": 1
        })
        assert success is True
        assert total == 10 # user_10 to user_19
        assert len(accounts) == 5
        assert accounts == ["user_10", "user_11", "user_12", "user_13", "user_14"]

        # List with pattern (page 2)
        success, msg, accounts, total = state_machine.apply_command({
            "type": "list_accounts", "username": "lister", "pattern": "user_1*", "page_size": 5, "page_num": 2
        })
        assert success is True
        assert total == 10
        assert len(accounts) == 5
        assert accounts == ["user_15", "user_16", "user_17", "user_18", "user_19"]

        # List for non-existent user (should fail)
        result = state_machine.apply_command({"type": "list_accounts", "username": "no_such_user"})
        assert result == (False, "Please log in first.", [], 0)

    def test_read_messages_unread(self, state_machine):
        """Test reading unread messages."""
        state_machine.apply_command({"type": "create_account", "username": "u1", "password_hash": "h"})
        state_machine.apply_command({"type": "create_account", "username": "u2", "password_hash": "h"})

        # Send messages
        ids = []
        for i in range(5):
            _, _, mid = state_machine.apply_command({"type": "send_message", "from_": "u2", "to": "u1", "content": f"msg {i}"})
            ids.append(mid)

        assert len(state_machine.db["accounts"]["u1"]["messages"]) == 5
        assert all(not m["read"] for m in state_machine.db["accounts"]["u1"]["messages"])

        # === First Read (page_num=1, page_size=3) ===
        result = state_machine.apply_command({
            "type": "read_messages", "username": "u1", "page_size": 3, "page_num": 1
        })
        success, msg, messages, total_msgs, remaining, total_unread, remaining_unread = result

        # Assertions for the FIRST read
        assert success is True
        assert len(messages) == 3  # Should get 3 messages
        assert messages[0]["content"] == "msg 0"
        assert messages[2]["content"] == "msg 2"
        assert total_unread == 5 # 5 were unread before this call
        assert remaining_unread == 2 # 2 left after reading 3
        assert all(m["read"] for m in messages) # Returned messages marked read

        # Verify state changes after FIRST read
        assert state_machine.db["accounts"]["u1"]["messages"][0]["read"] is True
        assert state_machine.db["accounts"]["u1"]["messages"][1]["read"] is True
        assert state_machine.db["accounts"]["u1"]["messages"][2]["read"] is True
        assert state_machine.db["accounts"]["u1"]["messages"][3]["read"] is False
        assert state_machine.db["accounts"]["u1"]["messages"][4]["read"] is False
        # Verify conversation state also updated
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][0]["read"] is True
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][1]["read"] is True
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][2]["read"] is True
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][3]["read"] is False
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][4]["read"] is False

        # === Second Read (page_num=2, page_size=3) ===
        result = state_machine.apply_command({
            "type": "read_messages", "username": "u1", "page_size": 3, "page_num": 2
        })
        success, msg, messages, total_msgs, remaining, total_unread, remaining_unread = result

        # Assertions for the SECOND read
        assert success is True
        # Page 2 (items starting at index 3) of the currently unread list ([m3, m4]) is empty.
        assert len(messages) == 0
        # total_unread reflects the count *before* this specific read operation.
        assert total_unread == 2
        # remaining_unread calculation: effective_end = min(start(3)+size(3), total(2)) = 2. remaining = max(0, 2-2) = 0
        assert remaining_unread == 0
        # all() is vacuously true for an empty list
        assert all(m["read"] for m in messages)

        # Verify state changes after SECOND read (no new messages marked read)
        assert state_machine.db["accounts"]["u1"]["messages"][3]["read"] is False # m3 still unread
        assert state_machine.db["accounts"]["u1"]["messages"][4]["read"] is False # m4 still unread
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][3]["read"] is False
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][4]["read"] is False

        # === Optional: Third Read (page_num=1 again) to get remaining ===
        result = state_machine.apply_command({
            "type": "read_messages", "username": "u1", "page_size": 3, "page_num": 1
        })
        success, msg, messages, total_msgs, remaining, total_unread, remaining_unread = result

        # Assertions for the THIRD read
        assert success is True
        assert len(messages) == 2 # Now page 1 gets m3, m4
        assert messages[0]["content"] == "msg 3"
        assert messages[1]["content"] == "msg 4"
        assert total_unread == 2 # 2 were unread before this call
        assert remaining_unread == 0 # 0 left after reading these 2
        assert all(m["read"] for m in messages)

        # Verify all messages are now read after THIRD read
        assert all(m["read"] for m in state_machine.db["accounts"]["u1"]["messages"])
        assert all(m["read"] for m in state_machine.db["accounts"]["u1"]["conversations"]["u2"])


    def test_read_messages_conversation(self, state_machine):
        """Test reading messages from a specific conversation."""
        state_machine.apply_command({"type": "create_account", "username": "u1", "password_hash": "h"})
        state_machine.apply_command({"type": "create_account", "username": "u2", "password_hash": "h"})
        state_machine.apply_command({"type": "create_account", "username": "u3", "password_hash": "h"})

        # Send messages from u2 to u1
        ids_u2 = []
        for i in range(5):
            _, _, mid = state_machine.apply_command({"type": "send_message", "from_": "u2", "to": "u1", "content": f"u2 msg {i}"})
            ids_u2.append(mid)
        # Send message from u3 to u1
        _, _, mid_u3 = state_machine.apply_command({"type": "send_message", "from_": "u3", "to": "u1", "content": "u3 msg"})

        assert len(state_machine.db["accounts"]["u1"]["messages"]) == 6
        assert len(state_machine.db["accounts"]["u1"]["conversations"]["u2"]) == 5
        assert len(state_machine.db["accounts"]["u1"]["conversations"]["u3"]) == 1

        # Read first page (size 3) of conversation with u2
        result = state_machine.apply_command({
            "type": "read_messages", "username": "u1", "chat_partner": "u2", "page_size": 3, "page_num": 1
        })
        success, msg, messages, total_msgs, remaining, total_unread, remaining_unread = result

        assert success is True
        assert msg == "Read conversation with u2."
        assert len(messages) == 3
        assert messages[0]["content"] == "u2 msg 0"
        assert messages[2]["content"] == "u2 msg 2"
        assert total_msgs == 5
        assert remaining == 2
        assert all(m["read"] for m in messages) # Returned messages marked read

        # Verify state changes (first 3 messages from u2 marked read)
        # Check main message list
        assert state_machine.db["accounts"]["u1"]["messages"][0]["read"] is True # u2 msg 0
        assert state_machine.db["accounts"]["u1"]["messages"][2]["read"] is True # u2 msg 2
        assert state_machine.db["accounts"]["u1"]["messages"][3]["read"] is False # u2 msg 3
        assert state_machine.db["accounts"]["u1"]["messages"][5]["read"] is False # u3 msg
        # Check conversation list
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][0]["read"] is True
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][2]["read"] is True
        assert state_machine.db["accounts"]["u1"]["conversations"]["u2"][3]["read"] is False
        # Check other conversation list (unaffected)
        assert state_machine.db["accounts"]["u1"]["conversations"]["u3"][0]["read"] is False

    def test_delete_message(self, state_machine):
        """Test deleting messages."""
        state_machine.apply_command({"type": "create_account", "username": "u1", "password_hash": "h"})
        state_machine.apply_command({"type": "create_account", "username": "u2", "password_hash": "h"})

        # Send messages
        _, _, mid1 = state_machine.apply_command({"type": "send_message", "from_": "u1", "to": "u2", "content": "msg 1"}, log_index=1)
        _, _, mid2 = state_machine.apply_command({"type": "send_message", "from_": "u2", "to": "u1", "content": "msg 2"}, log_index=2)
        _, _, mid3 = state_machine.apply_command({"type": "send_message", "from_": "u1", "to": "u2", "content": "msg 3"}, log_index=3)

        assert mid1 in state_machine.db["id_to_message"]
        assert mid2 in state_machine.db["id_to_message"]
        assert mid3 in state_machine.db["id_to_message"]
        assert len(state_machine.db["accounts"]["u1"]["messages"]) == 1 # msg 2
        assert len(state_machine.db["accounts"]["u2"]["messages"]) == 2 # msg 1, msg 3
        assert len(state_machine.db["accounts"]["u1"]["conversations"]["u2"]) == 1 # msg 2
        assert len(state_machine.db["accounts"]["u2"]["conversations"]["u1"]) == 2 # msg 1, msg 3

        # u1 deletes mid2 (sent by u2) and mid3 (sent by u1)
        result = state_machine.apply_command({
            "type": "delete_message", "username": "u1", "message_ids": [mid2, mid3]
        }, log_index=4)
        success, msg, affected_users = result

        assert success is True
        assert msg == "Deleted 2 messages."
        # u2 is affected because mid2 (sent to u1) and mid3 (sent to u2) involved them
        assert sorted(affected_users) == ["u2"]

        # Verify state
        assert mid1 in state_machine.db["id_to_message"] # Not deleted
        assert mid2 not in state_machine.db["id_to_message"]
        assert mid3 not in state_machine.db["id_to_message"]

        # Check u1's state (mid2 removed)
        assert len(state_machine.db["accounts"]["u1"]["messages"]) == 0
        assert len(state_machine.db["accounts"]["u1"]["conversations"]["u2"]) == 0

        # Check u2's state (mid3 removed)
        assert len(state_machine.db["accounts"]["u2"]["messages"]) == 1
        assert state_machine.db["accounts"]["u2"]["messages"][0]["id"] == mid1
        assert len(state_machine.db["accounts"]["u2"]["conversations"]["u1"]) == 1
        assert state_machine.db["accounts"]["u2"]["conversations"]["u1"][0]["id"] == mid1

    def test_delete_account(self, state_machine):
        """Test deleting an account."""
        state_machine.apply_command({"type": "create_account", "username": "user_to_delete", "password_hash": "h"}, log_index=1)
        assert "user_to_delete" in state_machine.db["accounts"]

        # Delete non-existent
        result = state_machine.apply_command({"type": "delete_account", "username": "non_existent"}, log_index=2)
        assert result == (False, "User does not exist.")

        # Delete existing
        result = state_machine.apply_command({"type": "delete_account", "username": "user_to_delete"}, log_index=3)
        assert result == (True, "Account 'user_to_delete' deleted.")
        assert "user_to_delete" not in state_machine.db["accounts"]

    def test_snapshot_trigger(self, state_machine, temp_data_dir, node_id):
        """Test automatic snapshot creation based on snapshot_interval."""
        sm_dir = temp_data_dir / node_id
        initial_snapshot_mtime = (sm_dir / "snapshot").stat().st_mtime
        initial_index_mtime = (sm_dir / "snapshot_index").stat().st_mtime

        # Create accounts (write operations)
        # state_machine fixture has snapshot_interval=3
        state_machine.apply_command({"type": "create_account", "username": "u1", "password_hash": "h"}, log_index=1)
        assert state_machine.commands_since_snapshot == 1
        assert state_machine.last_snapshot_index == 0
        state_machine.apply_command({"type": "create_account", "username": "u2", "password_hash": "h"}, log_index=2)
        assert state_machine.commands_since_snapshot == 2
        assert state_machine.last_snapshot_index == 0

        # This command should trigger the snapshot
        state_machine.apply_command({"type": "create_account", "username": "u3", "password_hash": "h"}, log_index=3)
        assert state_machine.commands_since_snapshot == 0 # Reset after snapshot
        assert state_machine.last_snapshot_index == 3 # Snapshot taken at log_index 3

        # Verify snapshot content
        with open(state_machine.snapshot_file, "rb") as f:
            snap_db = pickle.load(f)
        assert "u1" in snap_db["accounts"]
        assert "u2" in snap_db["accounts"]
        assert "u3" in snap_db["accounts"]
        with open(state_machine.snapshot_index_file, "r") as f:
            snap_idx = int(f.read().strip())
        assert snap_idx == 3

        # Apply another command, counter should increment again
        state_machine.apply_command({"type": "delete_account", "username": "u1"}, log_index=4)
        assert state_machine.commands_since_snapshot == 1
        assert state_machine.last_snapshot_index == 3 # No new snapshot yet

    def test_snapshot_persistence(self, temp_data_dir, node_id):
        """Test that state is correctly loaded from snapshot and subsequent commands work."""
        # Phase 1: Create initial state and trigger snapshot
        sm1 = StateMachine(node_id, data_dir=str(temp_data_dir), snapshot_interval=2)
        sm1.apply_command({"type": "create_account", "username": "user1", "password_hash": "h1"}, log_index=1)
        sm1.apply_command({"type": "send_message", "from_": "user1", "to": "user1", "content": "msg1"}, log_index=2) # Snapshot triggered here
        assert sm1.last_snapshot_index == 2
        assert "user1" in sm1.db["accounts"]
        assert len(sm1.db["accounts"]["user1"]["messages"]) == 1

        # Phase 2: Create new instance, should load from snapshot
        sm2 = StateMachine(node_id, data_dir=str(temp_data_dir), snapshot_interval=2)
        assert sm2.last_snapshot_index == 2
        assert "user1" in sm2.db["accounts"]
        assert len(sm2.db["accounts"]["user1"]["messages"]) == 1
        assert sm2.db["accounts"]["user1"]["messages"][0]["content"] == "msg1"
        assert sm2.commands_since_snapshot == 0 # Reset on load

        # Phase 3: Apply more commands to the new instance
        sm2.apply_command({"type": "create_account", "username": "user2", "password_hash": "h2"}, log_index=3)
        assert sm2.commands_since_snapshot == 1
        assert sm2.last_snapshot_index == 2
        sm2.apply_command({"type": "send_message", "from_": "user2", "to": "user1", "content": "msg2"}, log_index=4) # Snapshot triggered here
        assert sm2.commands_since_snapshot == 0
        assert sm2.last_snapshot_index == 4

        # Verify final state
        assert "user1" in sm2.db["accounts"]
        assert "user2" in sm2.db["accounts"]
        assert len(sm2.db["accounts"]["user1"]["messages"]) == 2
        assert sm2.db["accounts"]["user1"]["messages"][1]["content"] == "msg2"

        # Phase 4: Load again to verify the second snapshot
        sm3 = StateMachine(node_id, data_dir=str(temp_data_dir), snapshot_interval=2)
        assert sm3.last_snapshot_index == 4
        assert "user1" in sm3.db["accounts"]
        assert "user2" in sm3.db["accounts"]
        assert len(sm3.db["accounts"]["user1"]["messages"]) == 2
