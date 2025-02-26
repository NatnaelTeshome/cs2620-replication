import selectors
import socket
import json
import hashlib
import logging
import fnmatch
from datetime import datetime

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s] %(message)s')

with open("config.json", "r") as file:
    try:
        config = json.load(file)
    except Exception as e:
        print(e)
        logging.error(f"failed to load config: {e}")
        config = {}

HOST = config.get("HOST", "localhost")
PORT = config.get("PORT", 12345)

# Account structure includes both 'messages' and 'conversations' ===
# accounts = {
#   "alice": {
#       "password_hash": "...",
#       "messages": [  # all incoming messages for 'alice'
#           {"id": 1, "from": "bob", "to": "alice", "content": "Hello", "read": False},
#           {"id": 2, "from": "charlie", "to": "bob", content": "Hi there", "read": True},
#           ...
#       ],
#       "conversations": {  # same messages, but grouped by 'from'
#           "bob": [
#               {"id": 1, "content": "Hello", "read": False}
#               ...
#           ],
#           "charlie": [...],
#           ...
#       }
#   },
#   ...
# }
accounts = {}

# Maps message IDs to messages
id_to_message = {}

# Global counter used for message ID generation
global_message_id = 0

def get_unread_count(username):
    """
    Return number of unread messages for a user by scanning the 'messages' list.
    (i.e., total across all senders)
    """
    user_info = accounts.get(username, {})
    msgs = user_info.get("messages", [])
    return sum(1 for m in msgs if not m["read"])

class ClientState:
    """
    Holds per-client buffering, partial reads, etc.
    Also tracks which user is currently logged in (if any).
    """
    def __init__(self, sock):
        self.sock = sock
        self.addr = sock.getpeername()
        self.in_buffer = ""
        self.out_buffer = []
        self.current_user = None
        logging.debug(f"new clientstate created for {self.addr}")

    def queue_message(self, message_str):
        """
        Add a string (JSON-serialized response + newline) to the output buffer.
        """
        self.out_buffer.append(message_str)
        logging.debug(f"queued message for {self.addr}: {message_str.strip()}")

    def close(self):
        """
        Close this client's connection.
        """
        try:
            self.sock.close()
            logging.debug(f"closed connection for {self.addr}")
        except OSError as e:
            logging.error(f"error closing connection for {self.addr}: {e}")

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()
        logging.debug(f"chatserver initialized on {host}:{port}")

        # Keep track of which users are currently logged in.
        # Maps username -> ClientState
        self.logged_in_users = {}

    def start(self):
        """Set up the listening socket and start the event loop."""
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind((self.host, self.port))
        listen_sock.listen()
        listen_sock.setblocking(False)

        self.selector.register(listen_sock, selectors.EVENT_READ, data=None)
        print(f"[SERVER] Listening on {self.host}:{self.port} (selectors-based)")
        logging.info(f"listening on {self.host}:{self.port} (selectors-based)")

        try:
            while True:
                events = self.selector.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        self.accept_connection(key.fileobj)
                    else:
                        self.service_connection(key, mask)
        except KeyboardInterrupt:
            print("[SERVER] Shutting down server (CTRL+C).")
            logging.info("server shutdown via keyboard interrupt")
        finally:
            self.selector.close()
            logging.debug("selector closed")

    def accept_connection(self, sock):
        """Accept a new incoming client connection."""
        conn, addr = sock.accept()
        print(f"[SERVER] Accepted connection from {addr}")
        logging.info(f"accepted connection from {addr}")
        conn.setblocking(False)
        client_state = ClientState(conn)
        self.selector.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=client_state)

    def service_connection(self, key, mask):
        sock = key.fileobj
        client_state = key.data

        if mask & selectors.EVENT_READ:
            self.read_from_client(client_state)
        if mask & selectors.EVENT_WRITE:
            self.write_to_client(client_state)

    def read_from_client(self, client_state):
        """Read any incoming data, parse it by lines, handle JSON commands."""
        try:
            data = client_state.sock.recv(1024)
            logging.debug(f"received data from {client_state.addr}: {len(data)} bytes")
        except Exception as e:
            logging.error(f"error reading from {client_state.addr}: {e}")
            data = None

        if data:
            client_state.in_buffer += data.decode('utf-8')
            # Process line by line
            while True:
                if "\n" in client_state.in_buffer:
                    line, remainder = client_state.in_buffer.split("\n", 1)
                    client_state.in_buffer = remainder
                    line = line.strip()
                    if line:
                        logging.debug(f"processing line from {client_state.addr}: {line}")
                        self.process_command(client_state, line)
                else:
                    break
        else:
            self.disconnect_client(client_state)

    def write_to_client(self, client_state):
        """Send out any queued messages from out_buffer."""
        while client_state.out_buffer:
            msg_str = client_state.out_buffer.pop(0)
            try:
                client_state.sock.sendall(msg_str.encode('utf-8'))
                logging.debug(f"sent message to {client_state.addr}: {msg_str.strip()}")
            except Exception as e:
                logging.error(f"error sending message to {client_state.addr}: {e}")
                self.disconnect_client(client_state)
                break

    def process_command(self, client_state, line):
        """
        Decode JSON, then dispatch to the proper handler based on "action".
        """
        try:
            request = json.loads(line)
            logging.debug(f"decoded json from {client_state.addr}: {request}")
        except json.JSONDecodeError:
            logging.error(f"json decode error from {client_state.addr}: {line}")
            self.send_response(client_state, success=False, message="Invalid JSON.")
            return

        action = request.get("action", "").upper()
        logging.info(f"received action '{action}' from {client_state.addr}")

        if action == "USERNAME":
            self.check_username(client_state, request)
        elif action == "CREATE":
            self.create_account(client_state, request)
        elif action == "LOGIN":
            self.handle_login(client_state, request)
        elif action == "LIST_ACCOUNTS":
            self.handle_list_accounts(client_state, request)
        elif action == "SEND":
            self.handle_send(client_state, request)
        elif action == "READ":
            self.handle_read(client_state, request)
        elif action == "DELETE_MESSAGE":
            self.handle_delete_message(client_state, request)
        elif action == "DELETE_ACCOUNT":
            self.handle_delete_account(client_state)
        elif action == "LOGOUT":
            self.handle_logout(client_state)
        elif action == "QUIT":
            self.send_response(client_state, success=True, message="Connection closed.")
            self.disconnect_client(client_state)
        else:
            self.send_response(client_state, success=False,
                               message=f"Unknown action: {action}")

    def send_response(self, client_state, success=True, message="", data=None):
        """
        Enqueue a JSON response message for the client to read.
        """
        if client_state is None:
            logging.debug("No client_state provided!")
            return  # If no client_state to respond to, just skip
        resp = {"success": success, "message": message}
        if data is not None:
            resp["data"] = data
        resp_str = json.dumps(resp) + "\n"
        client_state.queue_message(resp_str)
        logging.debug(f"response sent to {client_state.addr}: {resp}")

    def push_event(self, client_state, event_name: str, event_payload: dict) -> None:
        """
        Enqueue a JSON event notification for the client to read.
        E.g., a new message has been received for the client to read
        """
        push_msg = {
            "event": event_name,
            "data": event_payload
        }
        push_str = json.dumps(push_msg) + "\n"
        client_state.queue_message(push_str)
        logging.debug(f"pushed event '{event_name}' to {client_state.addr}: {event_payload}")

    # Check if username exists
    def check_username(self, client_state, request):
        """Endpoint to check if a username exists."""
        username = request.get("username", "")
        if not username:
            logging.error("No username provided")
            self.send_response(client_state, success=False, message="Username not provided.")
            return
        
        if username in accounts:
            logging.debug("Username %s already taken", username)
            self.send_response(client_state, success=True, message="Username exists.")
        else:
            logging.debug("Username %s does not exists", username)
            self.send_response(client_state, success=False, message="Username does not exist.")

    # Create account
    def create_account(self, client_state, request):
        """Endpoint to create a new account and log the user in."""
        username = request.get("username", "")
        password_hash = request.get("password_hash", "")

        if not username or not password_hash:
            self.send_response(client_state, success=False, message="Username or password not provided.")
            logging.warning(f"create_account failed: missing username or password from {client_state.addr}")
            return

        if username in accounts:
            self.send_response(client_state, success=False, message="Username already exists.")
            logging.warning(f"create_account failed: username '{username}' already exists from {client_state.addr}")
            return

        accounts[username] = {
            "password_hash": password_hash,
            "messages": [],
            "conversations": {}
        }
        client_state.current_user = username

        # Register in logged_in_users
        self.logged_in_users[username] = client_state

        msg = f"New account '{username}' created and logged in."
        self.send_response(client_state, success=True, message=msg)
        logging.info(f"account '{username}' created and logged in from {client_state.addr}")

    # login
    def handle_login(self, client_state, request):
        username = request.get("username", "")
        password_hash = request.get("password_hash", "")

        if not username or not password_hash:
            self.send_response(client_state, success=False,
                               message="Username or password hash missing.")
            logging.warning(f"handle_login failed: missing credentials from {client_state.addr}")
            return

        if username not in accounts:
            self.send_response(client_state, success=False,
                               message="No such user.")
            logging.warning(f"handle_login failed: no such user '{username}' from {client_state.addr}")
            return

        # Check password
        if accounts[username]["password_hash"] != password_hash:
            self.send_response(client_state, success=False,
                               message="Incorrect password.")
            logging.warning(f"handle_login failed: incorrect password for '{username}' from {client_state.addr}")
            return

        # If another ClientState had been logged in, remove it. 
        if username in self.logged_in_users:
            old_state = self.logged_in_users[username]
            if old_state is not client_state:
                old_state.current_user = None
                logging.info(f"overwriting existing session for '{username}' from {client_state.addr}")

        client_state.current_user = username
        self.logged_in_users[username] = client_state

        unread_count = get_unread_count(username)
        self.send_response(client_state, success=True,
                           message=f"Logged in as '{username}'. Unread messages: {unread_count}.")
        logging.info(f"user '{username}' logged in from {client_state.addr}")

    def handle_list_accounts(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(
                client_state,
                success=False,
                message="Please log in first."
            )
            logging.warning(
                f"handle_list_accounts failed: not logged in {client_state.addr}"
            )
            return

        page_size = request.get("page_size", 10)
        page_num = request.get("page_num", 1)
        pattern = request.get("pattern", "*")  # By default, show all accounts

        # Use fnmatch to filter accounts that match the wildcard pattern
        matching_accounts = [
            account for account in accounts.keys() if fnmatch.fnmatch(account, pattern)
        ]
        # Sort the matching accounts
        matching_accounts.sort()
        total_accounts = len(matching_accounts)

        start_index = (page_num - 1) * page_size
        end_index = start_index + page_size

        if start_index >= total_accounts:
            page_accounts = []
        else:
            page_accounts = matching_accounts[start_index:end_index]

        data = {
            "total_accounts": total_accounts,
            "accounts": page_accounts
        }
        self.send_response(client_state, success=True, data=data)
        logging.debug(f"listed accounts for {client_state.addr}: page {page_num}")

    def _legacy_handle_list_accounts(self, client_state, request):
        # TODO: Remove this
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
            logging.warning(f"handle_list_accounts failed: not logged in {client_state.addr}")
            return

        page_size = request.get("page_size", 10)
        page_num = request.get("page_num", 1)
        pattern = request.get("pattern", "*") # By default, show all accounts

        # TODO: Implement wildcard matching of accounts using the user specified
        # pattern, and just return those

        all_accounts = sorted(accounts.keys())
        total_accounts = len(all_accounts)

        start_index = (page_num - 1) * page_size
        end_index = start_index + page_size

        if start_index >= total_accounts:
            page_accounts = []
        else:
            page_accounts = all_accounts[start_index:end_index]

        data = {
            "total_accounts": total_accounts,
            "accounts": page_accounts
        }
        self.send_response(client_state, success=True, data=data)
        logging.debug(f"listed accounts for {client_state.addr}: page {page_num}")

    def handle_send(self, client_state, request):
        """
        Send message from current user to a recipient.
        Also, if the recipient is logged in, push the message to them immediately.
        """
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
            logging.warning(f"handle_send failed: not logged in {client_state.addr}")
            return

        sender = client_state.current_user
        recipient = request.get("to", "")
        content = request.get("content", "").strip()

        if not recipient or not content:
            self.send_response(client_state, success=False,
                               message="Recipient or content missing.")
            logging.warning(f"handle_send failed: missing recipient or content from {client_state.addr}")
            return

        if recipient not in accounts:
            self.send_response(client_state, success=False,
                               message="Recipient does not exist.")
            logging.warning(f"handle_send failed: recipient '{to}' does not exist from {client_state.addr}")
            return

        global global_message_id
        global_message_id += 1
        msg_id = global_message_id

        # 1) Add to the recipient's "messages" list
        new_msg = {
            "id": msg_id,
            "from": sender,
            "to": recipient,
            "content": content,
            "read": False
        }
        accounts[recipient]["messages"].append(new_msg)

        # 2) Also add to the 'conversations' dictionary
        if sender not in accounts[recipient]["conversations"]:
            accounts[recipient]["conversations"][sender] = []
        accounts[recipient]["conversations"][sender].append({
            "id": msg_id,
            "content": content,
            "read": False
        })

        # 3) Finally, store in our ID to MSG mapping for O(1) lookups
        id_to_message[msg_id] = new_msg

        # Acknowledge to the sender
        self.send_response(client_state, success=True,
                           message=f"Message sent to '{recipient}': {content}",
                           data={'id':msg_id})
        logging.info(f"user '{sender}' sent message id {msg_id} to '{recipient}'")

        # If the recipient is logged in, push a notification
        recipient_state = self.logged_in_users.get(recipient)
        if recipient_state:
            self.push_event(
                recipient_state,
                "NEW_MESSAGE",
                {
                    "id": msg_id,
                    "from": sender,
                    "to": recipient,
                    "timestamp": int(datetime.now().strftime("%s")),
                    "content": content
                }
            )
            logging.info(f"pushed new message event to '{recipient}'")

    def handle_read(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
            logging.warning(f"handle_read failed: not logged in {client_state.addr}")
            return

        username = client_state.current_user
        chat_partner = request.get("chat_partner", None)

        page_size = request.get("page_size", 5)
        page_num = request.get("page_num", 1)

        if chat_partner:
            # Read from a specific conversation
            conversations = accounts[username].get("conversations", {})
            partner_msgs = conversations.get(chat_partner, [])

            total_msgs = len(partner_msgs)
            start_idx = (page_num - 1) * page_size
            end_idx = min(start_idx + page_size, total_msgs)

            if start_idx >= total_msgs:
                paginated = []
            else:
                paginated = partner_msgs[start_idx:end_idx]

            # Mark them as read
            for msg in paginated:
                msg["read"] = True

            # Also mark them as read in the 'messages' list
            all_msgs = accounts[username].get("messages", [])
            paginated_ids = {m["id"] for m in paginated}
            for m in all_msgs:
                if m["id"] in paginated_ids:
                    m["read"] = True

            self.send_response(
                client_state,
                success=True,
                data={
                    "conversation_with": chat_partner,
                    "messages": paginated,
                    "page_num": page_num,
                    "page_size": page_size,
                    "total_msgs": total_msgs,
                    "remaining": max(0, total_msgs - end_idx)
                }
            )
            logging.info(f"user '{username}' read conversation with '{chat_partner}'")
        else:
            # Read from the 'messages' list (unread only)
            user_msgs = accounts[username]["messages"]
            unread_msgs = [m for m in user_msgs if not m["read"]]

            total_unread = len(unread_msgs)
            start_index = (page_num - 1) * page_size
            end_index = min(start_index + page_size, total_unread)

            if start_index >= total_unread:
                to_read = []
            else:
                to_read = unread_msgs[start_index:end_index]

            # Mark them as read
            for m in to_read:
                m["read"] = True

            # Also mark them in 'conversations'
            conversations = accounts[username].get("conversations", {})
            for msg in to_read:
                snd = msg["from"]
                if snd in conversations:
                    for conv_msg in conversations[snd]:
                        if conv_msg["id"] == msg["id"]:
                            conv_msg["read"] = True

            self.send_response(
                client_state,
                success=True,
                data={
                    "read_messages": to_read,
                    "total_unread": total_unread,
                    "remaining_unread": max(0, total_unread - end_index)
                }
            )
            logging.info(f"user '{username}' read {len(to_read)} messages (unread)")

    def handle_delete_message(self, client_state, request) -> None:
        """
        Handles book-keeping of deleted messages on the server side,
        as well as notifies affected users (sender/recipient) of message deletion
        """
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="please log in first.")
            logging.warning(f"handle_delete_message failed: not logged in {client_state.addr}")
            return

        username = client_state.current_user
        message_ids = request.get("message_ids", [])
        if not isinstance(message_ids, list):
            message_ids = [message_ids]

        # find affected users efficiently
        affected_users = set()
        for msg_id in message_ids:
            msg = id_to_message.get(msg_id)
            if msg:
                affected_users.add(msg["from"])
                affected_users.add(msg["to"])

        affected_users.discard(username)
        logging.debug("message ids %s deleted. will notify users: %s", str(message_ids), str(affected_users))

        # remove messages from id_to_message and user's message list
        user_msgs = accounts.get(username, {}).get("messages", [])
        if isinstance(user_msgs, list):
            accounts[username]["messages"] = [m for m in user_msgs if m["id"] not in message_ids]

        for msg_id in message_ids:
            msg_obj = id_to_message.get(msg_id)
            if not msg_obj:
                logging.error("Message with ID %s doesn't exist?", str(msg_id))
                continue

            receiver = msg_obj["to"]

            # remove from receiver's message list
            receiver_msgs = accounts.get(receiver, {}).get("messages", [])
            if isinstance(receiver_msgs, list):
                accounts[receiver]["messages"] = [m for m in receiver_msgs if m["id"] not in message_ids]

            # remove from receiver's conversations
            receiver_conversations = accounts.get(receiver, {}).get("conversations", {})
            sender = msg_obj["from"]
            if sender in receiver_conversations and isinstance(receiver_conversations[sender], list):
                receiver_conversations[sender] = [m for m in receiver_conversations[sender] if m["id"] not in message_ids]

            # finally, remove from global lookup
            id_to_message.pop(msg_id, None)

        # also remove from conversations
        conversations = accounts[username]["conversations"]
        for partner in conversations:
            conversations[partner] = [m for m in conversations[partner] if m["id"] not in message_ids]

        # notify affected users
        for user in affected_users:
            if user in accounts:
                recipient_state = self.logged_in_users.get(user)
                if recipient_state:
                    self.push_event(recipient_state, "DELETE_MESSAGE", {"ids": message_ids})
                    logging.info(f"pushed DELETE_MESSAGE event to '{user}'")
            else:
                logging.error("cannot delete message for non-existent user %s", user)

        msg = f"deleted {len(message_ids)} messages."
        self.send_response(client_state, success=True, message=msg)
        logging.info(f"user '{username}' deleted {len(message_ids)} messages")

    def deprecated_handle_delete_message(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
            logging.warning(f"handle_delete_message failed: not logged in {client_state.addr}")
            return

        username = client_state.current_user
        message_ids = request.get("message_ids", [])
        if not isinstance(message_ids, list):
            message_ids = [message_ids]

        user_msgs = accounts[username]["messages"]
        before_count = len(user_msgs)

        # Before removing messages, find all affected users.
        # This is needed to notify them of the deletion
        affected_users = set()
        for msg in user_msgs:
            # TODO: We should instead have a table / hashmap
            # that directly maps IDs to messages, instead of
            # having to perform a linear scan
            if msg["id"] in message_ids:
                affected_users.add(msg["from"])
                affected_users.add(msg["to"])
        affected_users.discard(username)
        logging.debug("Message ids %s deleted. Will notify users: %s", str(message_ids), str(affected_users))

        # Remove from 'messages'
        new_msgs = [m for m in user_msgs if m["id"] not in message_ids]
        after_count = len(new_msgs)
        accounts[username]["messages"] = new_msgs

        # Also remove from 'conversations'
        conversations = accounts[username]["conversations"]
        for partner, msg_list in conversations.items():
            new_list = [m for m in msg_list if m["id"] not in message_ids]
            conversations[partner] = new_list

        # Notify affected users
        for user in affected_users:
            if user in accounts:
                recipient_state = self.logged_in_users.get(user, None)
                if not recipient_state:
                    # We don't notify users that are not currently logged in
                    continue
                self.push_event(
                    recipient_state,
                    "DELETE_MESSAGE",
                    {
                        "ids": message_ids,
                    }
                )
                logging.info(f"pushed DELETE_MESSAGE event to '{user}'")
            else:
                logging.error("Cannot delete message for non-existent user %s", user)

        deleted_count = before_count - after_count
        msg = f"Deleted {deleted_count} messages."
        self.send_response(client_state, success=True, message=msg)
        logging.info(f"user '{username}' deleted {deleted_count} messages")

    def handle_delete_account(self, client_state):
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
            logging.warning(f"handle_delete_account failed: not logged in {client_state.addr}")
            return

        username = client_state.current_user
        del accounts[username]
        # Also remove from logged_in_users
        self.logged_in_users.pop(username, None)

        client_state.current_user = None
        self.send_response(client_state, success=True,
                           message=f"Account '{username}' deleted.")
        logging.info(f"account '{username}' deleted")

    def handle_logout(self, client_state):
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="No user is currently logged in.")
            logging.warning(f"handle_logout failed: no user logged in from {client_state.addr}")
        else:
            user = client_state.current_user
            client_state.current_user = None
            self.logged_in_users.pop(user, None)
            self.send_response(client_state, success=True,
                               message=f"User '{user}' logged out.")
            logging.info(f"user '{user}' logged out from {client_state.addr}")

    def disconnect_client(self, client_state):
        """
        Unregister and close the client socket.
        If the client was logged in, remove it from logged_in_users.
        """
        print(f"[SERVER] Disconnecting {client_state.addr}")
        logging.info(f"disconnecting {client_state.addr}")
        self.selector.unregister(client_state.sock)

        if client_state.current_user in self.logged_in_users:
            self.logged_in_users.pop(client_state.current_user, None)

        client_state.close()

if __name__ == "__main__":
    server = ChatServer(HOST, PORT)
    server.start()
