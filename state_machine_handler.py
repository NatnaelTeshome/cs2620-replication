import logging
import fnmatch
from datetime import datetime

class StateMachineHandler:
    """Handler for applying commands to the state machine."""
    
    def __init__(self, state_machine):
        self.state_machine = state_machine
        self.logger = logging.getLogger("StateMachineHandler")
    
    def apply_command(self, command):
        """Apply a command to the state machine."""
        cmd_type = command["type"]
        self.logger.debug(f"Applying command: {cmd_type}")
        
        if cmd_type == "create_account":
            return self._create_account(command)
        elif cmd_type == "login":
            return self._login(command)
        elif cmd_type == "check_username":
            return self._check_username(command)
        elif cmd_type == "list_accounts":
            return self._list_accounts(command)
        elif cmd_type == "send_message":
            return self._send_message(command)
        elif cmd_type == "read_messages":
            return self._read_messages(command)
        elif cmd_type == "delete_message":
            return self._delete_message(command)
        elif cmd_type == "delete_account":
            return self._delete_account(command)
        elif cmd_type == "config_change":
            return self._config_change(command)
        else:
            self.logger.error(f"Unknown command type: {cmd_type}")
            return False, f"Unknown command type: {cmd_type}"
    
    def _create_account(self, command):
        """Create a new account."""
        username = command["username"]
        password_hash = command["password_hash"]
        
        # Apply to state machine
        success, message = self.state_machine.apply_command({
            "type": "create_account",
            "username": username,
            "password_hash": password_hash
        })
        
        return success, message
    
    def _login(self, command):
        """Log in to an account."""
        username = command["username"]
        password_hash = command["password_hash"]
        
        # Get accounts from state machine
        accounts = self.state_machine.get_accounts()
        
        if username not in accounts:
            return False, "No such user.", 0
        
        if accounts[username]["password_hash"] != password_hash:
            return False, "Incorrect password.", 0
        
        # Count unread messages
        unread = sum(1 for m in accounts[username]["messages"] if not m["read"])
        
        return True, f"Logged in as '{username}'. Unread messages: {unread}.", unread
    
    def _check_username(self, command):
        """Check if a username exists."""
        username = command["username"]
        
        # Get accounts from state machine
        accounts = self.state_machine.get_accounts()
        
        exists = username in accounts
        message = "Username exists." if exists else "Username does not exist."
        
        return exists, message
    
    def _list_accounts(self, command):
        """List accounts matching a pattern."""
        username = command["username"]
        pattern = command["pattern"] if "pattern" in command else "*"
        page_size = command["page_size"]
        page_num = command["page_num"]
        
        # Get accounts from state machine
        accounts = self.state_machine.get_accounts()
        
        if username not in accounts:
            return False, "Please log in first.", [], 0
        
        matching = [acct for acct in accounts.keys() if fnmatch.fnmatch(acct, pattern)]
        matching.sort()
        
        total = len(matching)
        start = (page_num - 1) * page_size
        end = start + page_size
        
        page_accounts = matching[start:end] if start < total else []
        
        return True, "", page_accounts, total
    
    def _send_message(self, command):
        """Send a message to another user."""
        sender = command["from_"]
        recipient = command["to"]
        content = command["content"]
        
        # Apply to state machine
        success, message, message_id = self.state_machine.apply_command({
            "type": "send_message",
            "from_": sender,
            "to": recipient,
            "content": content
        })
        
        return success, message, message_id
    
    def _read_messages(self, command):
        """Read messages for a user."""
        username = command["username"]
        page_size = command["page_size"]
        page_num = command["page_num"]
        chat_partner = command.get("chat_partner", "")
        
        # Get accounts from state machine
        accounts = self.state_machine.get_accounts()
        
        if username not in accounts:
            return False, "Please log in first.", [], 0, 0, 0, 0
        
        user_data = accounts[username]
        
        if chat_partner:
            # Read conversation with specific chat partner
            conv = user_data.get("conversations", {}).get(chat_partner, [])
            total_msgs = len(conv)
            start = (page_num - 1) * page_size
            end = min(start + page_size, total_msgs)
            
            messages = conv[start:end] if start < total_msgs else []
            
            # Mark messages as read
            for m in messages:
                success, _ = self.state_machine.apply_command({
                    "type": "read_message",
                    "username": username,
                    "message_id": m["id"]
                })
            
            remaining = max(0, total_msgs - end)
            
            return True, f"Read conversation with {chat_partner}.", messages, total_msgs, remaining, 0, 0
        else:
            # Read unread messages
            unread = [m for m in user_data.get("messages", []) if not m["read"]]
            total_unread = len(unread)
            start = (page_num - 1) * page_size
            end = min(start + page_size, total_unread)
            
            messages = unread[start:end] if start < total_unread else []
            
            # Mark messages as read
            for m in messages:
                success, _ = self.state_machine.apply_command({
                    "type": "read_message",
                    "username": username,
                    "message_id": m["id"]
                })
            
            remaining_unread = max(0, total_unread - end)
            
            return True, "Read unread messages.", messages, 0, 0, total_unread, remaining_unread
    
    def _delete_message(self, command):
        """Delete messages for a user."""
        username = command["username"]
        message_ids = command["message_ids"]
        
        # Apply to state machine
        success, message, affected_users = self.state_machine.apply_command({
            "type": "delete_message",
            "username": username,
            "message_ids": message_ids
        })
        
        return success, message, affected_users
    
    def _delete_account(self, command):
        """Delete an account."""
        username = command["username"]
        
        # Apply to state machine
        success, message = self.state_machine.apply_command({
            "type": "delete_account",
            "username": username
        })
        
        return success, message
    
    def _config_change(self, command):
        """Handle configuration changes."""
        # This is just for the state machine to acknowledge configuration changes
        return True, "Configuration change applied."