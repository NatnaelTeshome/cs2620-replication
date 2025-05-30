import os
import json
import shelve
import pickle
import logging
from datetime import datetime


class PersistentLog:
    def __init__(self, node_id, data_dir="./data"):
        self.node_id = node_id
        self.data_dir = os.path.join(data_dir, node_id)
        self.log_file = os.path.join(self.data_dir, "log")
        self.state_file = os.path.join(self.data_dir, "state")
        self.metadata_file = os.path.join(self.data_dir, "metadata.json")
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialize metadata
        self.metadata = self._load_metadata()
        
        # Initialize log storage
        self.log = []
        self.load_log()
    
    def _load_metadata(self):
        if os.path.exists(self.metadata_file):
            with open(self.metadata_file, "r") as f:
                return json.load(f)
        else:
            metadata = {
                "current_term": 0,
                "voted_for": None,
                "commit_index": 0,
                "last_applied": 0
            }
            self._save_metadata(metadata)
            return metadata
    
    def _save_metadata(self, metadata=None):
        with open(self.metadata_file, "w") as f:
            json.dump(metadata or self.metadata, f, indent=2)
    
    def get_current_term(self):
        return self.metadata["current_term"]
    
    def set_current_term(self, term):
        self.metadata["current_term"] = term
        self._save_metadata()
    
    def get_voted_for(self):
        return self.metadata["voted_for"]
    
    def set_voted_for(self, node_id):
        self.metadata["voted_for"] = node_id
        self._save_metadata()
    
    def get_commit_index(self):
        return self.metadata["commit_index"]
    
    def set_commit_index(self, index):
        self.metadata["commit_index"] = index
        self._save_metadata()
    
    def get_last_applied(self):
        return self.metadata["last_applied"]
    
    def set_last_applied(self, index):
        self.metadata["last_applied"] = index
        self._save_metadata()
    
    def append_entries(self, entries, start_index):
        """Append entries to log, possibly overwriting conflicting entries."""
        if start_index < len(self.log):
            # Overwrite conflicting entries
            self.log = self.log[:start_index]
        
        # Append new entries
        self.log.extend(entries)
        
        # Save to disk
        self._save_log()
        
        return True, len(self.log) - 1
    
    def get_entries(self, start_index, end_index=None):
        """Get log entries from start_index (inclusive) to end_index (exclusive)."""
        if start_index >= len(self.log):
            return []
        
        end = end_index if end_index and end_index <= len(self.log) else len(self.log)
        return self.log[start_index:end]
    
    def get_last_log_index(self):
        """Get the index of the last log entry."""
        return len(self.log) - 1 if self.log else -1
    
    def get_last_log_term(self):
        """Get the term of the last log entry."""
        if not self.log:
            return 0
        return self.log[-1]["term"]
    
    def load_log(self):
        """Load log from disk."""
        if os.path.exists(self.log_file):
            with open(self.log_file, "rb") as f:
                self.log = pickle.load(f)
        else:
            self.log = []
    
    def _save_log(self):
        """Save log to disk."""
        with open(self.log_file, "wb") as f:
            pickle.dump(self.log, f)


class StateMachine:
    def __init__(self, node_id, data_dir="./data", snapshot_interval=1000):
        self.node_id = node_id
        self.data_dir = os.path.join(data_dir, node_id)
        self.snapshot_file = os.path.join(self.data_dir, "snapshot")
        self.snapshot_index_file = os.path.join(self.data_dir, "snapshot_index")
        
        # Snapshot configuration
        self.snapshot_interval = snapshot_interval  # Take snapshot every N commands
        self.commands_since_snapshot = 0
        self.last_snapshot_index = 0
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Try to load from snapshot first
        if os.path.exists(self.snapshot_file) and os.path.exists(self.snapshot_index_file):
            self._load_snapshot()
        else:
            # Initialize empty state
            self.db = {
                "accounts": {},
                "id_to_message": {},
                "global_message_id": 0
            }
            self._save_snapshot(0)  # Initial snapshot at index 0
    
    def _load_snapshot(self):
        """Load state from snapshot."""
        try:
            with open(self.snapshot_file, 'rb') as f:
                self.db = pickle.load(f)
            
            with open(self.snapshot_index_file, 'r') as f:
                self.last_snapshot_index = int(f.read().strip())
            
            self.commands_since_snapshot = 0
            logging.info(f"Loaded snapshot at index {self.last_snapshot_index}")
        except Exception as e:
            logging.error(f"Error loading snapshot: {e}")
            # Initialize empty state as fallback
            self.db = {
                "accounts": {},
                "id_to_message": {},
                "global_message_id": 0
            }
            self._save_snapshot(0)
    
    def _save_snapshot(self, log_index):
        """Save current state as snapshot."""
        try:
            with open(self.snapshot_file, 'wb') as f:
                pickle.dump(self.db, f)
            
            with open(self.snapshot_index_file, 'w') as f:
                f.write(str(log_index))
            
            self.last_snapshot_index = log_index
            self.commands_since_snapshot = 0
            logging.info(f"Saved snapshot at index {log_index}")
        except Exception as e:
            logging.error(f"Error saving snapshot: {e}")
    
    def apply_command(self, command, log_index=None):
        """Apply a command to the state machine."""
        cmd_type = command["type"]
        result = None
        # apply login
        if cmd_type == "check_username":
            result = self._check_username(command["username"])
        elif cmd_type == "login":
            result = self._login(command["username"], command["password_hash"])
        elif cmd_type == "list_accounts":
            result = self._list_accounts(
                command["username"],
                command.get("pattern", "*"),
                command.get("page_size", 10),
                command.get("page_num", 1),
            )
        elif cmd_type == "create_account":
            result = self._create_account(command["username"], command["password_hash"])
        elif cmd_type == "send_message":
            result = self._send_message(command["from_"], command["to"], command["content"])
        elif cmd_type == "read_messages":
            result = self._read_messages(command["username"], command.get("page_size", 10), 
                                        command.get("page_num", 1), command.get("chat_partner", None))
        elif cmd_type == "delete_message":
            result = self._delete_message(command["username"], command["message_ids"])
        elif cmd_type == "delete_account":
            result = self._delete_account(command["username"])
        else:
            logging.error(f"Unknown command type: {cmd_type}")
            return False, "Unknown command type."
        
        # Check if we should create a snapshot (only for write operations)
        if log_index is not None and cmd_type in ["create_account", "send_message", "delete_message", "delete_account"]:
            self.commands_since_snapshot += 1
            
            if self.commands_since_snapshot >= self.snapshot_interval:
                self._save_snapshot(log_index)
        
        return result

    def _check_username(self, username):
        """Check if a username exists."""
        accounts = self.db["accounts"]
        
        exists = username in accounts
        message = "Username exists." if exists else "Username does not exist."
        
        return exists, message

    def _login(self, username, password_hash):
        """Log in to an account."""
        accounts = self.db["accounts"]
        
        if username not in accounts:
            return False, "No such user.", 0
        
        if accounts[username]["password_hash"] != password_hash:
            return False, "Incorrect password.", 0
        
        # Count unread messages
        unread = sum(1 for m in accounts[username]["messages"] if not m["read"])
        
        return True, f"Logged in as '{username}'. Unread messages: {unread}.", unread

    def _list_accounts(self, username, pattern="*", page_size=10, page_num=1):
        """List accounts matching a pattern."""
        accounts = self.db["accounts"]
        
        if username not in accounts:
            return False, "Please log in first.", [], 0
        
        import fnmatch
        matching = [acct for acct in accounts.keys() if fnmatch.fnmatch(acct, pattern)]
        matching.sort()
        
        total = len(matching)
        start = (page_num - 1) * page_size
        end = start + page_size
        
        page_accounts = matching[start:end] if start < total else []
        
        return True, "", page_accounts, total

    def _create_account(self, username, password_hash):
        """Create a new account."""
        accounts = self.db["accounts"]
        
        if username in accounts:
            return False, "Username already exists."
        
        accounts[username] = {
            "password_hash": password_hash,
            "messages": [],
            "conversations": {},
        }
        
        return True, f"New account '{username}' created."
    
    def _send_message(self, sender, recipient, content):
        """Send a message to another user."""
        accounts = self.db["accounts"]
        id_to_message = self.db["id_to_message"]
        
        if recipient not in accounts:
            return False, "Recipient does not exist."
        
        global_message_id = self.db["global_message_id"] + 1
        self.db["global_message_id"] = global_message_id
        
        timestamp = int(datetime.now().timestamp())
        
        new_msg = {
            "id": global_message_id,
            "from_": sender,
            "to": recipient,
            "content": content,
            "read": False,
            "timestamp": timestamp,
        }
        
        # Append to recipient's messages list
        accounts[recipient]["messages"].append(new_msg)
        
        # Append to conversations
        conv = accounts[recipient]["conversations"]
        if sender not in conv:
            conv[sender] = []
        conv[sender].append(new_msg)
        
        # Save in global mapping
        id_to_message[global_message_id] = new_msg
        
        return True, f"Message sent to '{recipient}': {content}", global_message_id
    
    def _read_messages(self, username, page_size=10, page_num=1, chat_partner=None):
        """Read messages for a user, either from a conversation or unread messages."""
        accounts = self.db["accounts"]
        
        if username not in accounts:
            return False, "Please log in first.", [], 0, 0, 0, 0
        
        user_data = accounts[username]
        messages = []
        total_msgs = 0
        remaining = 0
        total_unread = 0
        remaining_unread = 0
        
        if chat_partner:
            # Read conversation with specific chat partner
            conv = user_data.get("conversations", {}).get(chat_partner, [])
            total_msgs = len(conv)
            start = (page_num - 1) * page_size
            end = min(start + page_size, total_msgs)
            
            messages = conv[start:end] if start < total_msgs else []
            
            # Mark messages as read in conversation and in messages list
            for m in messages:
                m["read"] = True
            
            for m in user_data.get("messages", []):
                if m["id"] in {msg["id"] for msg in messages}:
                    m["read"] = True
            
            remaining = max(0, total_msgs - end)
            
            return True, f"Read conversation with {chat_partner}.", messages, total_msgs, remaining, 0, 0
        else:
            # Read unread messages
            unread = [m for m in user_data.get("messages", []) if not m["read"]]
            total_unread = len(unread)
            start = (page_num - 1) * page_size
            end = min(start + page_size, total_unread)
            
            messages = unread[start:end] if start < total_unread else []
            
            # Mark them as read
            for m in messages:
                m["read"] = True
            
            # Also mark in conversations
            message_ids_to_mark = {m["id"] for m in messages} # Get IDs efficiently
            for m in messages:
                sender = m["from_"]
                if sender in user_data.get("conversations", {}):
                    for conv_msg in user_data["conversations"][sender]:
                        if conv_msg["id"] == m["id"]:
                            conv_msg["read"] = True

            # Also mark in the main messages list
            for main_msg in user_data.get("messages", []):
                if main_msg["id"] in message_ids_to_mark:
                    main_msg["read"] = True
            
            remaining_unread = max(0, total_unread - end)
            
            return True, "Read unread messages.", messages, 0, 0, total_unread, remaining_unread
    
    def _delete_message(self, username, message_ids):
        """Delete messages for a user."""
        accounts = self.db["accounts"]
        id_to_message = self.db["id_to_message"]
        
        if username not in accounts:
            return False, "User does not exist."
        
        affected_users = set()
        
        # Remove messages from the initiating user's messages list
        accounts[username]["messages"] = [
            m for m in accounts[username].get("messages", [])
            if m["id"] not in message_ids
        ]
        
        # Process each message id
        for mid in message_ids:
            msg_obj = id_to_message.get(mid)
            if not msg_obj:
                logging.error(f"Message with ID {mid} does not exist.")
                continue
            
            sender = msg_obj["from_"]
            receiver = msg_obj["to"]
            affected_users.add(sender)
            affected_users.add(receiver)
            
            # Remove from receiver's messages
            if receiver in accounts:
                accounts[receiver]["messages"] = [
                    m for m in accounts[receiver].get("messages", [])
                    if m["id"] != mid
                ]
                
                # Remove from receiver's conversations
                conv = accounts[receiver].get("conversations", {}).get(sender, [])
                accounts[receiver]["conversations"][sender] = [
                    m for m in conv if m["id"] != mid
                ]
            
            # Also remove from sender's conversations if present
            if sender in accounts:
                conv = accounts[sender].get("conversations", {}).get(receiver, [])
                accounts[sender]["conversations"][receiver] = [
                    m for m in conv if m["id"] != mid
                ]
            
            id_to_message.pop(mid, None)
        
        # Remove the initiating user from affected set
        affected_users.discard(username)
        
        return True, f"Deleted {len(message_ids)} messages.", list(affected_users)
    
    def _delete_account(self, username):
        """Delete an account."""
        accounts = self.db["accounts"]
        
        if username not in accounts:
            return False, "User does not exist."
        
        del accounts[username]
        
        return True, f"Account '{username}' deleted."
    
    # def get_accounts(self):
    #     """Get a copy of all accounts."""
    #     return dict(self.db["accounts"])
    
    # def get_id_to_message(self):
    #     """Get a copy of the ID to message mapping."""
    #     return dict(self.db["id_to_message"])
    
    # def get_global_message_id(self):
    #     """Get the current global message ID."""
    #     return self.db["global_message_id"]
    
    def get_last_snapshot_index(self):
        """Get the log index of the last snapshot."""
        return self.last_snapshot_index
