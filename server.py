import selectors
import socket
import json
import hashlib

with open("config.json", "r") as file:
    config = json.load(file)

HOST = config["HOST"]
PORT = config["PORT"]

accounts = {}
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

    def queue_message(self, message_str):
        """
        Add a string (JSON-serialized response + newline) to the output buffer.
        """
        self.out_buffer.append(message_str)

    def close(self):
        """
        Close this client's connection.
        """
        try:
            self.sock.close()
        except OSError:
            pass

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()

        # NEW: Keep track of which users are currently logged in.
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
        finally:
            self.selector.close()

    def accept_connection(self, sock):
        """Accept a new incoming client connection."""
        conn, addr = sock.accept()
        print(f"[SERVER] Accepted connection from {addr}")
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
        except Exception:
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
            except Exception:
                self.disconnect_client(client_state)
                break

    def process_command(self, client_state, line):
        """
        Decode JSON, then dispatch to the proper handler based on "action".
        """
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            self.send_response(client_state, success=False, message="Invalid JSON.")
            return

        action = request.get("action", "").upper()

        if action == "USERNAME":
            self.check_username(request)
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
            return  # If no client_state to respond to, just skip
        resp = {"success": success, "message": message}
        if data is not None:
            resp["data"] = data
        resp_str = json.dumps(resp) + "\n"
        client_state.queue_message(resp_str)

    # Check if username exists
    def check_username(self, request):
        """Endpoint to check if a username exists."""
        username = request.get("username", "")
        if not username:
            # We have no client_state to respond to here (in original code).
            return
        
        if username in accounts:
            # Typically you'd respond to the *requester*,
            # but original code just sends a success/fail with no state.
            pass
        else:
            pass
        # No changes; if you actually want to return something, you'd do:
        # self.send_response(client_state, success=..., message=...)

    # Create account
    def create_account(self, client_state, request):
        """Endpoint to create a new account and log the user in."""
        username = request.get("username", "")
        password_hash = request.get("password_hash", "")

        if not username or not password_hash:
            self.send_response(client_state, success=False, message="Username or password not provided.")
            return

        if username in accounts:
            self.send_response(client_state, success=False, message="Username already exists.")
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

    # login
    def handle_login(self, client_state, request):
        username = request.get("username", "")
        password_hash = request.get("password_hash", "")

        if not username or not password_hash:
            self.send_response(client_state, success=False,
                               message="Username or password hash missing.")
            return

        if username not in accounts:
            self.send_response(client_state, success=False,
                               message="No such user.")
            return

        # Check password
        if accounts[username]["password_hash"] != password_hash:
            self.send_response(client_state, success=False,
                               message="Incorrect password.")
            return

        # If another ClientState had been logged in, remove it. 
        # (Optional: depends on whether you want to allow multi-logins.)
        if username in self.logged_in_users:
            # you could forcibly disconnect the old session if desired,
            # or just overwrite. We'll just overwrite for simplicity:
            old_state = self.logged_in_users[username]
            if old_state is not client_state:
                old_state.current_user = None

        client_state.current_user = username
        self.logged_in_users[username] = client_state

        unread_count = get_unread_count(username)
        self.send_response(client_state, success=True,
                           message=f"Logged in as '{username}'. Unread messages: {unread_count}.")

    def handle_list_accounts(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
            return

        page_size = request.get("page_size", 10)
        page_num = request.get("page_num", 1)

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

    def handle_send(self, client_state, request):
        """
        Send message from current user to a recipient.
        Also, if the recipient is logged in, push the message to them immediately.
        """
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
            return

        sender = client_state.current_user
        recipient = request.get("recipient", "")
        content = request.get("content", "").strip()

        if not recipient or not content:
            self.send_response(client_state, success=False,
                               message="Recipient or content missing.")
            return

        if recipient not in accounts:
            self.send_response(client_state, success=False,
                               message="Recipient does not exist.")
            return

        global global_message_id
        global_message_id += 1
        msg_id = global_message_id

        # 1) Add to the recipient's "messages" list
        new_msg = {
            "id": msg_id,
            "sender": sender,
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

        # Acknowledge to the sender
        self.send_response(client_state, success=True,
                           message=f"Message sent to '{recipient}': {content}")

        # NEW: If the recipient is logged in, push a notification
        recipient_state = self.logged_in_users.get(recipient)
        if recipient_state:
            # We can push either a small message or the full message data
            push_data = {
                "action": "NEW_MESSAGE",
                "message": {
                    "id": msg_id,
                    "sender": sender,
                    "content": content
                }
            }
            # Use send_response (or a dedicated push method).
            # Mark success=True so the client knows it's a valid push event
            self.send_response(
                recipient_state,
                success=True,
                message=f"New message from '{sender}'",
                data=push_data
            )

    def handle_read(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
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
                snd = msg["sender"]
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

    def handle_delete_message(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
            return

        username = client_state.current_user
        message_ids = request.get("message_ids", [])
        if not isinstance(message_ids, list):
            message_ids = [message_ids]

        user_msgs = accounts[username]["messages"]
        before_count = len(user_msgs)

        # Remove from 'messages'
        new_msgs = [m for m in user_msgs if m["id"] not in message_ids]
        after_count = len(new_msgs)
        accounts[username]["messages"] = new_msgs

        # Also remove from 'conversations'
        conversations = accounts[username]["conversations"]
        for partner, msg_list in conversations.items():
            new_list = [m for m in msg_list if m["id"] not in message_ids]
            conversations[partner] = new_list

        deleted_count = before_count - after_count
        msg = f"Deleted {deleted_count} messages."
        self.send_response(client_state, success=True, message=msg)

    def handle_delete_account(self, client_state):
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="Please log in first.")
            return

        username = client_state.current_user
        del accounts[username]
        # Also remove from logged_in_users
        self.logged_in_users.pop(username, None)

        client_state.current_user = None
        self.send_response(client_state, success=True,
                           message=f"Account '{username}' deleted.")

    def handle_logout(self, client_state):
        if client_state.current_user is None:
            self.send_response(client_state, success=False,
                               message="No user is currently logged in.")
        else:
            user = client_state.current_user
            client_state.current_user = None
            self.logged_in_users.pop(user, None)
            self.send_response(client_state, success=True,
                               message=f"User '{user}' logged out.")

    def disconnect_client(self, client_state):
        """
        Unregister and close the client socket.
        If the client was logged in, remove it from logged_in_users.
        """
        print(f"[SERVER] Disconnecting {client_state.addr}")
        self.selector.unregister(client_state.sock)

        if client_state.current_user in self.logged_in_users:
            self.logged_in_users.pop(client_state.current_user, None)

        client_state.close()

if __name__ == "__main__":
    server = ChatServer(HOST, PORT)
    server.start()
