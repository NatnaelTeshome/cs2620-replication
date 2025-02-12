import selectors
import socket
import json
import hashlib
import logging
import struct
import fnmatch
import shelve

logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s] [%(levelname)s] %(message)s')

with open("config.json", "r") as file:
    try:
        config = json.load(file)
    except Exception as e:
        print(e)
        logging.error(f"failed to load config: {e}")
        config = {}

HOST = config.get("HOST", "localhost")
PORT = config.get("PORT", 12345)

# --- Persistent storage using shelve ---
db = shelve.open("chat_db", writeback=True)

if "accounts" in db:
    accounts = db["accounts"]
else:
    accounts = {}
    db["accounts"] = accounts

if "id_to_message" in db:
    id_to_message = db["id_to_message"]
else:
    id_to_message = {}
    db["id_to_message"] = id_to_message

if "global_message_id" in db:
    global_message_id = db["global_message_id"]
else:
    global_message_id = 0
    db["global_message_id"] = global_message_id

def persist_data():
    db["accounts"] = accounts
    db["id_to_message"] = id_to_message
    db["global_message_id"] = global_message_id
    db.sync()

# --- Protocol and encoding functions ---

OP_CODES_DICT = {
    "LOGIN": 1,
    "CREATE_ACCOUNT": 2,
    "DELETE_ACCOUNT": 3,
    "LIST_ACCOUNTS": 4,
    "SEND_MESSAGE": 5,
    "READ_MESSAGES": 6,
    "DELETE_MESSAGE": 7,
    "CHECK_USERNAME": 8,
    "QUIT": 9
}

EVENT_TYPES = {
    "NEW_MESSAGE": 0,
    "DELETE_MESSAGE": 1
}

def encode_list_accounts_data(data: dict) -> bytes:
    total_accounts = data.get("total_accounts", 0)
    accounts_list = data.get("accounts", [])
    encoded = struct.pack("!I", total_accounts)
    encoded += struct.pack("!H", len(accounts_list))
    for acct in accounts_list:
        acct_bytes = acct.encode("utf-8")
        encoded += struct.pack("!H", len(acct_bytes)) + acct_bytes
    return encoded

def encode_conversation_data(data: dict) -> bytes:
    conv_with = data.get("conversation_with", "")
    conv_bytes = conv_with.encode("utf-8")
    page_num = data.get("page_num", 0)
    page_size = data.get("page_size", 0)
    total_msgs = data.get("total_msgs", 0)
    remaining = data.get("remaining", 0)
    messages = data.get("messages", [])
    result = struct.pack("!B", 1)  # flag for conversation response
    result += struct.pack("!H", len(conv_bytes)) + conv_bytes
    result += struct.pack("!HH", page_num, page_size)
    result += struct.pack("!II", total_msgs, remaining)
    result += struct.pack("!H", len(messages))
    for msg in messages:
        msg_id = msg.get("id", 0)
        content = msg.get("content", "")
        content_bytes = content.encode("utf-8")
        read_flag = 1 if msg.get("read", False) else 0
        result += struct.pack("!I", msg_id)
        result += struct.pack("!H", len(content_bytes)) + content_bytes
        result += struct.pack("!B", read_flag)
    return result

def encode_unread_data(data: dict) -> bytes:
    total_unread = data.get("total_unread", 0)
    remaining_unread = data.get("remaining_unread", 0)
    messages = data.get("read_messages", [])
    # flag 0 for general unread type
    result = struct.pack("!BII", 0, total_unread, remaining_unread)
    result += struct.pack("!H", len(messages))
    for msg in messages:
        logging.debug(f"Encoding message: {msg}")
        msg_id = msg.get("id", 0)
        sender = msg.get("sender", "")
        sender_bytes = sender.encode("utf-8")
        content = msg.get("content", "")
        content_bytes = content.encode("utf-8")
        read_flag = 1 if msg.get("read", False) else 0
        result += struct.pack("!I", msg_id)
        result += struct.pack("!H", len(sender_bytes)) + sender_bytes
        result += struct.pack("!H", len(content_bytes)) + content_bytes
        result += struct.pack("!B", read_flag)
    return result

def encode_response_bin(success: bool, message: str = "",
                        data_bytes: bytes = b"", op_code: int = 0) -> bytes:
    success_byte = 1 if success else 0
    message_bytes = message.encode("utf-8") if message else b""
    payload = struct.pack(f"!B H {len(message_bytes)}s H",
                          success_byte,
                          len(message_bytes),
                          message_bytes,
                          len(data_bytes))
    payload += data_bytes
    header = struct.pack("!BBH", VERSION, op_code, len(payload))
    return header + payload

def encode_event(event_type: int, data_bytes: bytes) -> bytes:
    payload = struct.pack("!B", event_type) + data_bytes
    header = struct.pack("!BBH", VERSION, 0, len(payload))
    return header + payload

def encode_new_message_event(data: dict) -> bytes:
    msg_id = data.get("id", 0)
    sender = data.get("sender", "")
    content = data.get("content", "")
    sender_bytes = sender.encode("utf-8")
    content_bytes = content.encode("utf-8")
    fmt = f"!I H{len(sender_bytes)}s H{len(content_bytes)}s"
    return struct.pack(fmt, msg_id, len(sender_bytes), sender_bytes,
                       len(content_bytes), content_bytes)

def encode_delete_message_event(data: dict) -> bytes:
    msg_ids = data.get("message_ids", [])
    count = len(msg_ids)
    fmt = f"!B{count}I"
    return struct.pack(fmt, count, *msg_ids)

def decode_message_from_buffer(buffer: bytes):
    logging.debug(f"Raw buffer message: {buffer}")
    if len(buffer) < 2:
        return None, 0
    version, op_code = struct.unpack("!BB", buffer[:2])
    if version != VERSION:
        raise ValueError("Unsupported protocol version")
    req = {"opcode": op_code}
    # LOGIN and CREATE_ACCOUNT: !BBH{username}sH{password_hash}s
    if op_code in (OP_CODES_DICT["LOGIN"], OP_CODES_DICT["CREATE_ACCOUNT"]):
        if len(buffer) < 4:
            return None, 0
        (username_len,) = struct.unpack("!H", buffer[2:4])
        if len(buffer) < 4 + username_len + 2:
            return None, 0
        username_bytes = buffer[4:4+username_len]
        pos = 4 + username_len
        (password_len,) = struct.unpack("!H", buffer[pos:pos+2])
        if len(buffer) < pos + 2 + password_len:
            return None, 0
        password_bytes = buffer[pos+2: pos+2+password_len]
        total_consumed = pos + 2 + password_len
        req["action"] = "LOGIN" if op_code == OP_CODES_DICT["LOGIN"] else "CREATE_ACCOUNT"
        req["username"] = username_bytes.decode("utf-8")
        req["password_hash"] = password_bytes.decode("utf-8")
        return req, total_consumed

    elif op_code == OP_CODES_DICT["DELETE_ACCOUNT"]:
        req["action"] = "DELETE_ACCOUNT"
        return req, 2

    elif op_code == OP_CODES_DICT["LIST_ACCOUNTS"]:
        header_size = 8  # version (1), opcode (1), page_size (2), page_num (2), pattern_len (2)
        if len(buffer) < header_size:
            return None, 0
        version, op_code = struct.unpack("!BB", buffer[:2])
        page_size, page_num, pattern_len = struct.unpack("!HHH", buffer[2:8])
        total_needed = header_size + pattern_len
        if len(buffer) < total_needed:
            return None, 0
        pattern_bytes = buffer[8:8+pattern_len]
        req["action"] = "LIST_ACCOUNTS"
        req["page_size"] = page_size
        req["page_num"] = page_num
        req["pattern"] = pattern_bytes.decode("utf-8")
        return req, total_needed

    elif op_code == OP_CODES_DICT["SEND_MESSAGE"]:
        if len(buffer) < 4:
            return None, 0
        (recipient_len,) = struct.unpack("!H", buffer[2:4])
        if len(buffer) < 4 + recipient_len + 2:
            return None, 0
        recipient_bytes = buffer[4:4+recipient_len]
        pos = 4 + recipient_len
        (message_len,) = struct.unpack("!H", buffer[pos:pos+2])
        if len(buffer) < pos + 2 + message_len:
            return None, 0
        message_bytes = buffer[pos+2: pos+2+message_len]
        total_consumed = pos + 2 + message_len
        req["action"] = "SEND_MESSAGE"
        req["recipient"] = recipient_bytes.decode("utf-8")
        req["content"] = message_bytes.decode("utf-8")
        return req, total_consumed

    elif op_code == OP_CODES_DICT["READ_MESSAGES"]:
        if len(buffer) < 7:
            return None, 0
        page_size, page_num = struct.unpack("!HH", buffer[2:6])
        flag = struct.unpack("!B", buffer[6:7])[0]
        pos = 7
        req["action"] = "READ_MESSAGES"
        req["page_size"] = page_size
        req["page_num"] = page_num
        if flag == 1:
            if len(buffer) < pos + 2:
                return None, 0
            (partner_len,) = struct.unpack("!H", buffer[pos:pos+2])
            pos += 2
            if len(buffer) < pos + partner_len:
                return None, 0
            partner_bytes = buffer[pos:pos+partner_len]
            pos += partner_len
            req["chat_partner"] = partner_bytes.decode("utf-8")
        return req, pos

    elif op_code == OP_CODES_DICT["DELETE_MESSAGE"]:
        if len(buffer) < 3:
            return None, 0
        count = struct.unpack("!B", buffer[2:3])[0]
        total_needed = 2 + 1 + count * 4
        if len(buffer) < total_needed:
            return None, 0
        message_ids = []
        for i in range(count):
            offset = 3 + i * 4
            msg_id = struct.unpack("!I", buffer[offset:offset+4])[0]
            message_ids.append(msg_id)
        req["action"] = "DELETE_MESSAGE"
        req["message_ids"] = message_ids
        return req, total_needed

    elif op_code == OP_CODES_DICT["CHECK_USERNAME"]:
        if len(buffer) < 4:
            return None, 0
        (username_len,) = struct.unpack("!H", buffer[2:4])
        total_needed = 2 + 2 + username_len
        if len(buffer) < total_needed:
            return None, 0
        username_bytes = buffer[4:4+username_len]
        req["action"] = "CHECK_USERNAME"
        req["username"] = username_bytes.decode("utf-8")
        return req, total_needed

    elif op_code == OP_CODES_DICT["QUIT"]:
        req["action"] = "QUIT"
        return req, 2

    else:
        logging.error("Unknown opcode received: %s", op_code)
        return None, len(buffer)

VERSION = 1

# --- ClientState and ChatServer classes ---

class ClientState:
    def __init__(self, sock):
        self.sock = sock
        self.addr = sock.getpeername()
        self.in_buffer = b""
        self.out_buffer = []
        self.current_user = None
        logging.debug(f"new clientstate created for {self.addr}")

    def queue_message(self, message_bytes):
        self.out_buffer.append(message_bytes)
        logging.debug(f"queued message for {self.addr}: {message_bytes}")

    def close(self):
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
        self.logged_in_users = {}

    def start(self):
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
            db.close()

    def accept_connection(self, sock):
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
        try:
            data = client_state.sock.recv(1024)
            logging.debug(f"received data from {client_state.addr}: {len(data)} bytes")
        except Exception as e:
            logging.error(f"error reading from {client_state.addr}: {e}")
            data = None
        if data:
            client_state.in_buffer += data
            try:
                while True:
                    req, consumed = decode_message_from_buffer(client_state.in_buffer)
                    if req is None or consumed == 0:
                        break
                    client_state.in_buffer = client_state.in_buffer[consumed:]
                    logging.debug(f"Decoded request from {client_state.addr}: {req}")
                    self.process_command(client_state, req)
            except Exception as e:
                logging.error(f"error processing buffer: {e}")
        else:
            self.disconnect_client(client_state)

    def write_to_client(self, client_state):
        while client_state.out_buffer:
            msg = client_state.out_buffer.pop(0)
            try:
                client_state.sock.sendall(msg)
                logging.debug(f"sent message to {client_state.addr}: {msg}")
            except Exception as e:
                logging.error(f"error sending message to {client_state.addr}: {e}")
                self.disconnect_client(client_state)
                break

    def process_command(self, client_state, request):
        action = request.get("action", "").upper()
        logging.info(f"received action '{action}' from {client_state.addr}")
        if action == "CHECK_USERNAME":
            self.check_username(client_state, request)
        elif action == "CREATE_ACCOUNT":
            self.create_account(client_state, request)
        elif action == "LOGIN":
            self.handle_login(client_state, request)
        elif action == "LIST_ACCOUNTS":
            self.handle_list_accounts(client_state, request)
        elif action == "SEND_MESSAGE":
            self.handle_send(client_state, request)
        elif action == "READ_MESSAGES":
            self.handle_read(client_state, request)
        elif action == "DELETE_MESSAGE":
            self.handle_delete_message(client_state, request)
        elif action == "DELETE_ACCOUNT":
            self.handle_delete_account(client_state)
        elif action == "LOGOUT":
            self.handle_logout(client_state)
        elif action == "QUIT":
            self.send_response(client_state, success=True, message="Connection closed.",
                               req_opcode=OP_CODES_DICT["QUIT"])
            self.disconnect_client(client_state)
        else:
            self.send_response(client_state, success=False,
                               message=f"Unknown action: {action}")

    def send_response(self, client_state, success=True, message="", data=None, req_opcode=0):
        if data is not None:
            if "total_accounts" in data and "accounts" in data:
                data_bytes = encode_list_accounts_data(data)
            elif "conversation_with" in data and "messages" in data:
                data_bytes = encode_conversation_data(data)
            elif "read_messages" in data and "total_unread" in data:
                data_bytes = encode_unread_data(data)
            else:
                logging.error("Something went wrong. Fallback: encoding data as JSON.")
                data_bytes = json.dumps(data).encode("utf-8")
        else:
            data_bytes = b""
        response_bytes = encode_response_bin(success, message, data_bytes, req_opcode)
        client_state.queue_message(response_bytes)
        logging.debug(f"response sent to {client_state.addr}: success={success}, message='{message}', data_bytes={data_bytes}")

    def push_event(self, client_state, event_type: str, event_payload: dict) -> None:
        if event_type == "NEW_MESSAGE":
            event_specific_payload = encode_new_message_event(event_payload)
            etype_code = EVENT_TYPES["NEW_MESSAGE"]
        elif event_type == "DELETE_MESSAGE":
            event_specific_payload = encode_delete_message_event(event_payload)
            etype_code = EVENT_TYPES["DELETE_MESSAGE"]
        else:
            logging.error(f"unknown event type: {event_type}")
            return
        push_bytes = encode_event(etype_code, event_specific_payload)
        client_state.queue_message(push_bytes)
        logging.debug(f"pushed event {event_type} to {client_state.addr}")

    def check_username(self, client_state, request):
        username = request.get("username", "")
        if not username:
            logging.error("No username provided")
            self.send_response(client_state, success=False, message="Username not provided.",
                               req_opcode=request.get("opcode"))
            return
        if username in accounts:
            logging.debug("Username %s already taken", username)
            self.send_response(client_state, success=True, message="Username exists.",
                               req_opcode=request.get("opcode"))
        else:
            logging.debug("Username %s does not exist", username)
            self.send_response(client_state, success=False, message="Username does not exist.",
                               req_opcode=request.get("opcode"))

    def create_account(self, client_state, request):
        username = request.get("username", "")
        password_hash = request.get("password_hash", "")
        if not username or not password_hash:
            self.send_response(client_state, success=False, message="Username or password not provided.",
                               req_opcode=request.get("opcode"))
            logging.warning(f"create_account failed: missing credentials from {client_state.addr}")
            return
        if username in accounts:
            self.send_response(client_state, success=False, message="Username already exists.",
                               req_opcode=request.get("opcode"))
            logging.warning(f"create_account failed: username '{username}' exists from {client_state.addr}")
            return
        accounts[username] = {
            "password_hash": password_hash,
            "messages": [],
            "conversations": {}
        }
        client_state.current_user = username
        self.logged_in_users[username] = client_state
        msg = f"New account '{username}' created and logged in."
        self.send_response(client_state, success=True, message=msg,
                               req_opcode=request.get("opcode"))
        logging.info(f"account '{username}' created and logged in from {client_state.addr}")
        persist_data()

    def handle_login(self, client_state, request):
        req_opcode = request.get("opcode")
        username = request.get("username", "")
        password_hash = request.get("password_hash", "")
        if not username or not password_hash:
            self.send_response(
                client_state,
                success=False,
                message="missing credentials.",
                req_opcode=req_opcode,
            )
            logging.warning(
                f"handle_login failed: missing credentials from {client_state.addr}"
            )
            return
        if username not in accounts:
            self.send_response(
                client_state,
                success=False,
                message="no such user.",
                req_opcode=req_opcode,
            )
            logging.warning(
                f"handle_login failed: no such user '{username}' from {client_state.addr}"
            )
            return
        if accounts[username]["password_hash"] != password_hash:
            self.send_response(
                client_state,
                success=False,
                message="incorrect password.",
                req_opcode=req_opcode,
            )
            logging.warning(
                f"handle_login failed: incorrect password for '{username}' from {client_state.addr}"
            )
            return
        if username in self.logged_in_users:
            old_state = self.logged_in_users[username]
            if old_state is not client_state:
                old_state.current_user = None
                logging.info(
                    f"overwriting session for '{username}' from {client_state.addr}"
                )
        client_state.current_user = username
        self.logged_in_users[username] = client_state
        unread_count = sum(1 for m in accounts[username].get("messages", []) if not m["read"])
        self.send_response(
            client_state,
            success=True,
            message=f"logged in as '{username}'. unread messages: {unread_count}.",
            req_opcode=req_opcode,
        )
        logging.info(f"user '{username}' logged in from {client_state.addr}")

    def handle_list_accounts(self, client_state, request):
        req_opcode = request.get("opcode")
        if client_state.current_user is None:
            self.send_response(
                client_state,
                success=False,
                message="Please log in first.",
                req_opcode=req_opcode,
            )
            logging.warning(
                f"handle_list_accounts failed: not logged in {client_state.addr}"
            )
            return
        page_size = request.get("page_size", 10)
        page_num = request.get("page_num", 1)
        pattern = request.get("pattern", "*")
        matching_accounts = [acct for acct in accounts.keys() if fnmatch.fnmatch(acct, pattern)]
        matching_accounts.sort()
        total_accounts = len(matching_accounts)
        start_index = (page_num - 1) * page_size
        end_index = start_index + page_size
        page_accounts = matching_accounts[start_index:end_index] if start_index < total_accounts else []
        data = {"total_accounts": total_accounts, "accounts": page_accounts}
        self.send_response(client_state, success=True, data=data, req_opcode=req_opcode)
        logging.debug(f"listed accounts for {client_state.addr}: page {page_num}")

    def handle_send(self, client_state, request):
        req_opcode = request.get("opcode")
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="please log in first.",
                               req_opcode=req_opcode)
            logging.warning(f"handle_send failed: not logged in {client_state.addr}")
            return
        sender = client_state.current_user
        recipient = request.get("recipient", "")
        content = request.get("content", "").strip()
        if not recipient or not content:
            self.send_response(client_state, success=False, message="recipient or content missing.",
                               req_opcode=req_opcode)
            logging.warning(f"handle_send failed: missing data from {client_state.addr}")
            return
        if recipient not in accounts:
            self.send_response(client_state, success=False, message="recipient does not exist.",
                               req_opcode=req_opcode)
            logging.warning(f"handle_send failed: recipient '{recipient}' not found from {client_state.addr}")
            return
        global global_message_id
        global_message_id += 1
        msg_id = global_message_id
        new_msg = {"id": msg_id, "sender": sender, "content": content, "read": False}
        accounts[recipient]["messages"].append(new_msg)
        if sender not in accounts[recipient]["conversations"]:
            accounts[recipient]["conversations"][sender] = []
        accounts[recipient]["conversations"][sender].append(
            {"id": msg_id, "content": content, "read": False}
        )
        self.send_response(client_state, success=True,
                           message=f"message sent to '{recipient}': {content}",
                           req_opcode=req_opcode)
        logging.info(f"user '{sender}' sent message id {msg_id} to '{recipient}'")
        recipient_state = self.logged_in_users.get(recipient)
        if recipient_state:
            self.push_event(recipient_state, "NEW_MESSAGE",
                            {"id": msg_id, "sender": sender, "content": content})
            logging.info(f"pushed new message event to '{recipient}'")
        persist_data()

    def handle_read(self, client_state, request):
        req_opcode = request.get("opcode")
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="please log in first.",
                               req_opcode=req_opcode)
            logging.warning(f"handle_read failed: not logged in {client_state.addr}")
            return
        username = client_state.current_user
        chat_partner = request.get("chat_partner", None)
        page_size = request.get("page_size", 5)
        page_num = request.get("page_num", 1)
        if chat_partner is not None:
            conversations = accounts[username].get("conversations", {})
            partner_msgs = conversations.get(chat_partner, [])
            total_msgs = len(partner_msgs)
            start_idx = (page_num - 1) * page_size
            end_idx = min(start_idx + page_size, total_msgs)
            paginated = partner_msgs[start_idx:end_idx] if start_idx < total_msgs else []
            for msg in paginated:
                msg["read"] = True
            all_msgs = accounts[username].get("messages", [])
            paginated_ids = {m["id"] for m in paginated}
            for m in all_msgs:
                if m["id"] in paginated_ids:
                    m["read"] = True
            data = {"conversation_with": chat_partner,
                    "messages": paginated,
                    "page_num": page_num,
                    "page_size": page_size,
                    "total_msgs": total_msgs,
                    "remaining": max(0, total_msgs - end_idx)}
            self.send_response(client_state, success=True, data=data, req_opcode=req_opcode)
            logging.info(f"user '{username}' read conversation with '{chat_partner}'")
        else:
            user_msgs = accounts[username]["messages"]
            unread_msgs = [m for m in user_msgs if not m["read"]]
            total_unread = len(unread_msgs)
            start_index = (page_num - 1) * page_size
            end_index = min(start_index + page_size, total_unread)
            to_read = unread_msgs[start_index:end_index] if start_index < total_unread else []
            for m in to_read:
                m["read"] = True
            conversations = accounts[username].get("conversations", {})
            for msg in to_read:
                snd = msg["sender"]
                if snd in conversations:
                    for conv_msg in conversations[snd]:
                        if conv_msg["id"] == msg["id"]:
                            conv_msg["read"] = True
            data = {"read_messages": to_read,
                    "total_unread": total_unread,
                    "remaining_unread": max(0, total_unread - end_index)}
            logging.debug(f"Data to be sent over the wire: {data}")
            self.send_response(client_state, success=True, data=data, req_opcode=req_opcode)
            logging.info(f"user '{username}' read {len(to_read)} unread messages")
        persist_data()

    def handle_delete_message(self, client_state, request):
        req_opcode = request.get("opcode")
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="please log in first.",
                               req_opcode=req_opcode)
            logging.warning(f"handle_delete_message failed: not logged in {client_state.addr}")
            return
        username = client_state.current_user
        message_ids = request.get("message_ids", [])
        if not isinstance(message_ids, list):
            message_ids = [message_ids]
        affected_users = set()
        for msg_id in message_ids:
            msg = id_to_message.get(msg_id)
            if msg:
                affected_users.add(msg["from"])
                affected_users.add(msg["to"])
        affected_users.discard(username)
        logging.debug("message ids %s deleted. will notify users: %s",
                      str(message_ids), str(affected_users))
        user_msgs = accounts.get(username, {}).get("messages", [])
        if isinstance(user_msgs, list):
            accounts[username]["messages"] = [m for m in user_msgs if m["id"] not in message_ids]
        for msg_id in message_ids:
            msg_obj = id_to_message.get(msg_id)
            if not msg_obj:
                logging.error("message with id %s doesn't exist?", str(msg_id))
                continue
            receiver = msg_obj["to"]
            receiver_msgs = accounts.get(receiver, {}).get("messages", [])
            if isinstance(receiver_msgs, list):
                accounts[receiver]["messages"] = [m for m in receiver_msgs if m["id"] not in message_ids]
            receiver_conversations = accounts.get(receiver, {}).get("conversations", {})
            sender = msg_obj["from"]
            if sender in receiver_conversations and isinstance(receiver_conversations[sender], list):
                receiver_conversations[sender] = [m for m in receiver_conversations[sender] if m["id"] not in message_ids]
            id_to_message.pop(msg_id, None)
        conversations = accounts[username]["conversations"]
        for partner in conversations:
            conversations[partner] = [m for m in conversations[partner] if m["id"] not in message_ids]
        for user in affected_users:
            if user in accounts:
                recipient_state = self.logged_in_users.get(user)
                if recipient_state:
                    self.push_event(recipient_state, "DELETE_MESSAGE", {"ids": message_ids})
                    logging.info(f"pushed DELETE_MESSAGE event to '{user}'")
            else:
                logging.error("cannot delete message for non-existent user %s", user)
        new_msgs = accounts[username]["messages"]
        deleted_count = len(user_msgs) - len(new_msgs)
        msg = f"deleted {deleted_count} messages."
        self.send_response(client_state, success=True, message=msg, req_opcode=req_opcode)
        logging.info(f"user '{username}' deleted {deleted_count} messages")
        persist_data()

    def handle_delete_account(self, client_state):
        req_opcode = OP_CODES_DICT["DELETE_ACCOUNT"]
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="please log in first.",
                               req_opcode=req_opcode)
            logging.warning(f"handle_delete_account failed: not logged in {client_state.addr}")
            return
        username = client_state.current_user
        del accounts[username]
        self.logged_in_users.pop(username, None)
        client_state.current_user = None
        self.send_response(client_state, success=True, message=f"account '{username}' deleted.",
                           req_opcode=req_opcode)
        logging.info(f"account '{username}' deleted")
        persist_data()

    def handle_logout(self, client_state):
        req_opcode = None
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="no user is currently logged in.",
                               req_opcode=req_opcode)
            logging.warning(f"handle_logout failed: no user logged in from {client_state.addr}")
        else:
            user = client_state.current_user
            client_state.current_user = None
            self.logged_in_users.pop(user, None)
            self.send_response(client_state, success=True, message=f"user '{user}' logged out.",
                               req_opcode=req_opcode)
            logging.info(f"user '{user}' logged out from {client_state.addr}")

    def disconnect_client(self, client_state):
        logging.info(f"disconnecting {client_state.addr}")
        self.selector.unregister(client_state.sock)
        if client_state.current_user in self.logged_in_users:
            self.logged_in_users.pop(client_state.current_user, None)
        client_state.close()

if __name__ == "__main__":
    server = ChatServer(HOST, PORT)
    server.start()
