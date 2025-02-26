import json
import pytest
from server_no_persistence import (
    ChatServer,
    ClientState,
    accounts,
    id_to_message,
    global_message_id,
    get_unread_count,
)

# A minimal fake socket for testing purposes.
class FakeSocket:
    def __init__(self, peername=("127.0.0.1", 10000)):
        self._peername = peername
        self.sent_data = b""
        self.closed = False

    def getpeername(self):
        return self._peername

    def sendall(self, data):
        self.sent_data += data

    def close(self):
        self.closed = True

    def recv(self, bufsize):
        return b''  # for tests that do not simulate input

# Reset globals before each test.
@pytest.fixture(autouse=True)
def reset_globals():
    accounts.clear()
    id_to_message.clear()
    global global_message_id
    global_message_id = 0

# Create a ChatServer instance and override unregister to be a no‐op.
@pytest.fixture
def server():
    srv = ChatServer("localhost", 12345)
    srv.selector.unregister = lambda sock: None
    return srv

# Provide a ClientState with a FakeSocket.
@pytest.fixture
def client_state():
    return ClientState(FakeSocket())

def test_get_unread_count():
    accounts["alice"] = {"messages": [{"read": False}, {"read": True}, {"read": False}]}
    assert get_unread_count("alice") == 2
    assert get_unread_count("bob") == 0

def test_check_username(server, client_state):
    # When username is not in accounts.
    req = {"username": "alice"}
    server.check_username(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert not resp["success"]
    assert "does not exist" in resp["message"]

    # Add an account and check again.
    accounts["alice"] = {"password_hash": "dummy", "messages": [], "conversations": {}}
    server.check_username(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert resp["success"]
    assert "exists" in resp["message"]

def test_create_account(server, client_state):
    req = {"username": "alice", "password_hash": "hash"}
    server.create_account(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert resp["success"]
    assert "created" in resp["message"]
    assert "alice" in accounts
    assert client_state.current_user == "alice"

    # Attempt duplicate creation.
    client_state.out_buffer.clear()
    server.create_account(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert not resp["success"]
    assert "already exists" in resp["message"]

def test_handle_login(server, client_state):
    accounts["alice"] = {"password_hash": "hash", "messages": [], "conversations": {}}
    # Missing credentials.
    req = {"username": "alice"}
    server.handle_login(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert not resp["success"]

    # Incorrect password.
    req = {"username": "alice", "password_hash": "wrong"}
    server.handle_login(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert not resp["success"]

    # Correct login.
    req = {"username": "alice", "password_hash": "hash"}
    server.handle_login(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert resp["success"]
    assert "Logged in as" in resp["message"]
    assert client_state.current_user == "alice"

def test_list_accounts(server, client_state):
    # Not logged in → error.
    req = {"page_size": 2, "page_num": 1, "pattern": "*"}
    server.handle_list_accounts(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert not resp["success"]

    # Now log in and add several accounts.
    client_state.current_user = "alice"
    accounts["alice"] = {"password_hash": "hash", "messages": [], "conversations": {}}
    accounts["bob"] = {"password_hash": "hash", "messages": [], "conversations": {}}
    accounts["charlie"] = {"password_hash": "hash", "messages": [], "conversations": {}}
    req = {"page_size": 2, "page_num": 1, "pattern": "b*"}
    server.handle_list_accounts(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    data = resp.get("data", {})
    assert resp["success"]
    assert data.get("total_accounts") == 1
    assert data.get("accounts") == ["bob"]

def test_handle_send(server, client_state):
    # Set up sender and recipient accounts.
    accounts["alice"] = {"password_hash": "hash", "messages": [], "conversations": {}}
    accounts["bob"] = {"password_hash": "hash", "messages": [], "conversations": {}}
    client_state.current_user = "alice"
    # Create a bob ClientState and mark him as logged in.
    bob_state = ClientState(FakeSocket(("127.0.0.1", 10001)))
    server.logged_in_users["bob"] = bob_state

def test_handle_read_without_chat_partner(server, client_state):
    accounts["alice"] = {"messages": [], "conversations": {}}
    client_state.current_user = "alice"
    # Insert two unread messages.
    msg1 = {"id": 1, "from": "bob", "to": "alice", "content": "Hi", "read": False}
    msg2 = {"id": 2, "from": "charlie", "to": "alice", "content": "Hello", "read": False}
    accounts["alice"]["messages"].extend([msg1, msg2])
    accounts["alice"]["conversations"] = {
        "bob": [{"id": 1, "content": "Hi", "read": False}],
        "charlie": [{"id": 2, "content": "Hello", "read": False}],
    }
    req = {"page_size": 1, "page_num": 1}
    server.handle_read(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    data = resp.get("data", {})
    assert resp["success"]
    read_msgs = data.get("read_messages")
    assert len(read_msgs) == 1
    assert read_msgs[0]["read"] is True

def test_handle_read_with_chat_partner(server, client_state):
    accounts["alice"] = {"messages": [], "conversations": {"bob": []}}
    client_state.current_user = "alice"
    msg = {"id": 1, "content": "Hi", "read": False}
    accounts["alice"]["conversations"]["bob"].append(msg)
    accounts["alice"]["messages"].append({"id": 1, "from": "bob", "to": "alice", "content": "Hi", "read": False})
    req = {"chat_partner": "bob", "page_size": 1, "page_num": 1}
    server.handle_read(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    data = resp.get("data", {})
    assert resp["success"]
    assert data.get("conversation_with") == "bob"
    messages = data.get("messages")
    assert len(messages) == 1
    assert messages[0]["read"] is True

def test_handle_delete_message(server, client_state):
    # Set up a message from alice to bob.
    accounts["alice"] = {
        "messages": [],  # typically, sender's "messages" list remains empty
        "conversations": {"bob": [{"id": 1, "content": "Hi", "read": False}]},
    }
    accounts["bob"] = {
        "messages": [{"id": 1, "from": "alice", "to": "bob", "content": "Hi", "read": False}],
        "conversations": {"alice": [{"id": 1, "content": "Hi", "read": False}]},
    }
    id_to_message[1] = {"id": 1, "from": "alice", "to": "bob", "content": "Hi", "read": False}
    client_state.current_user = "alice"
    bob_state = ClientState(FakeSocket(("127.0.0.1", 10001)))
    server.logged_in_users["bob"] = bob_state

    req = {"message_ids": [1]}
    server.handle_delete_message(client_state, req)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert resp["success"]
    # Verify that the message is removed from both alice’s and bob’s accounts.
    assert all(m["id"] != 1 for m in accounts["alice"].get("messages", []))
    assert all(m["id"] != 1 for m in accounts["bob"].get("messages", []))
    assert 1 not in id_to_message
    # Bob should have received a deletion event.
    evt = json.loads(bob_state.out_buffer.pop(0))
    assert evt.get("event") == "DELETE_MESSAGE"
    assert 1 in evt["data"]["ids"]

def test_handle_delete_account(server, client_state):
    accounts["alice"] = {"password_hash": "hash", "messages": [], "conversations": {}}
    client_state.current_user = "alice"
    server.logged_in_users["alice"] = client_state
    server.handle_delete_account(client_state)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert resp["success"]
    assert "deleted" in resp["message"]
    assert "alice" not in accounts
    assert client_state.current_user is None
    assert "alice" not in server.logged_in_users

def test_handle_logout(server, client_state):
    client_state.current_user = "alice"
    server.logged_in_users["alice"] = client_state
    server.handle_logout(client_state)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert resp["success"]
    assert "logged out" in resp["message"]
    assert client_state.current_user is None
    assert "alice" not in server.logged_in_users

def test_process_invalid_json(server, client_state):
    bad_line = "not a json"
    server.process_command(client_state, bad_line)
    resp = json.loads(client_state.out_buffer.pop(0))
    assert not resp["success"]
    assert "Invalid JSON" in resp["message"]

def test_process_unknown_action(server, client_state):
    req = {"action": "FOO"}
    server.process_command(client_state, json.dumps(req))
    resp = json.loads(client_state.out_buffer.pop(0))
    assert not resp["success"]
    assert "Unknown action" in resp["message"]

def test_quit_command(server, client_state):
    disconnected = False
    def fake_disconnect(cs):
        nonlocal disconnected
        disconnected = True
    server.disconnect_client = fake_disconnect
    req = {"action": "QUIT"}
    server.process_command(client_state, json.dumps(req))
    resp = json.loads(client_state.out_buffer.pop(0))
    assert resp["success"]
    assert "Connection closed" in resp["message"]
    assert disconnected