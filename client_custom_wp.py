import socket
import json
import threading
import queue
import hashlib
from typing import Optional, Dict, Any, List
import struct

VERSION = 1

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

def encode_login(payload) -> bytes:
    op_code = OP_CODES_DICT["LOGIN"]
    username = payload.get("username")
    password = payload.get("password")
    username_bytes = username.encode("utf-8")
    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    password_bytes = password_hash.encode("utf-8")
    # Format: Version (B), Opcode (B), username length (H), username, password length (H), password_hash
    fmt = f"!BBH{len(username_bytes)}sH{len(password_bytes)}s"
    return struct.pack(fmt, VERSION, op_code,
                       len(username_bytes), username_bytes,
                       len(password_bytes), password_bytes)

def encode_create_account(payload) -> bytes:
    op_code = OP_CODES_DICT["CREATE_ACCOUNT"]
    username = payload.get("username")
    password = payload.get("password")
    username_bytes = username.encode("utf-8")
    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    password_bytes = password_hash.encode("utf-8")
    # Same format as LOGIN.
    fmt = f"!BBH{len(username_bytes)}sH{len(password_bytes)}s"
    return struct.pack(fmt, VERSION, op_code,
                       len(username_bytes), username_bytes,
                       len(password_bytes), password_bytes)

def encode_delete_account() -> bytes:
    op_code = OP_CODES_DICT["DELETE_ACCOUNT"]
    # No additional payload.
    return struct.pack("!BB", VERSION, op_code)

def encode_list_accounts(payload) -> bytes:
    op_code = OP_CODES_DICT["LIST_ACCOUNTS"]
    page_size = payload.get("page_size")
    page_num = payload.get("page_num")
    pattern = payload.get("pattern")
    pattern_bytes = pattern.encode("utf-8")
    # Format: Version (B), Opcode (B), page_size (H), page_num (H), pattern_len (H) pattern_bytes (H{len(pattern_bytes)}s)
    return struct.pack(f"!BBHHH{len(pattern_bytes)}s", VERSION, op_code, page_size, page_num, len(pattern_bytes), pattern_bytes)

def encode_send_message(payload) -> bytes:
    op_code = OP_CODES_DICT["SEND_MESSAGE"]
    recipient = payload.get("recipient")
    message = payload.get("message")
    recipient_bytes = recipient.encode("utf-8")
    message_bytes = message.encode("utf-8")
    # Format: Version (B), Opcode (B), recipient length (H), recipient, message length (H), message
    fmt = f"!BBH{len(recipient_bytes)}sH{len(message_bytes)}s"
    return struct.pack(fmt, VERSION, op_code,
                       len(recipient_bytes), recipient_bytes,
                       len(message_bytes), message_bytes)

def encode_read_messages(payload) -> bytes:
    op_code = OP_CODES_DICT["READ_MESSAGES"]
    page_size = payload.get("page_size")
    page_num = payload.get("page_num")
    chat_partner = payload.get("chat_partner")
    # Base: Version (B), Opcode (B), page_size (H), page_num (H)
    base = struct.pack("!BBHH", VERSION, op_code, page_size, page_num)
    if chat_partner:
        partner_bytes = chat_partner.encode("utf-8")
        # Flag (B) = 1 indicates partner provided, then partner length (H) and partner bytes.
        fmt = f"!BH{len(partner_bytes)}s"
        return base + struct.pack(fmt, 1, len(partner_bytes), partner_bytes)
    else:
        # Flag (B) = 0 indicates no chat partner.
        return base + struct.pack("!B", 0)

def encode_delete_message(payload) -> bytes:
    op_code = OP_CODES_DICT["DELETE_MESSAGE"]
    message_ids = payload.get("message_ids")
    count = len(message_ids)
    # Format: Version (B), Opcode (B), count (B), then each message id as unsigned int (I)
    fmt = f"!BBB{count}I"
    return struct.pack(fmt, VERSION, op_code, count, *message_ids)

def encode_check_username(payload) -> bytes:
    op_code = OP_CODES_DICT["CHECK_USERNAME"]
    username = payload.get("username")
    username_bytes = username.encode("utf-8")
    # Format: Version (B), Opcode (B), username length (H), username
    fmt = f"!BBH{len(username_bytes)}s"
    return struct.pack(fmt, VERSION, op_code, len(username_bytes), username_bytes)

def encode_quit() -> bytes:
    op_code = OP_CODES_DICT["QUIT"]
    return struct.pack("!BB", VERSION, op_code)

# Map actions to their encoder functions.
encoder_map = {
    "LOGIN": encode_login,
    "CREATE_ACCOUNT": encode_create_account,
    "DELETE_ACCOUNT": encode_delete_account,
    "LIST_ACCOUNTS": encode_list_accounts,
    "SEND_MESSAGE": encode_send_message,
    "READ_MESSAGES": encode_read_messages,
    "DELETE_MESSAGE": encode_delete_message,
    "CHECK_USERNAME": encode_check_username,
    "QUIT": encode_quit,
}

# ---------------------------------------------------------------------------
# Helper to decode the binary-encoded data part of a response.
# We try to decode as one of the known structures.
# ---------------------------------------------------------------------------
def decode_data_bytes(data_bytes: bytes) -> Any:
    # Try to decode as list_accounts data:
    try:
        if len(data_bytes) >= 6:
            # Unpack total_accounts (I) and account_count (H)
            total_accounts = struct.unpack("!I", data_bytes[:4])[0]
            account_count = struct.unpack("!H", data_bytes[4:6])[0]
            pos = 6
            accounts = []
            for i in range(account_count):
                if len(data_bytes) < pos + 2:
                    raise ValueError("Insufficient data for account length")
                name_len = struct.unpack("!H", data_bytes[pos:pos+2])[0]
                pos += 2
                if len(data_bytes) < pos + name_len:
                    raise ValueError("Insufficient data for account name")
                name = data_bytes[pos:pos+name_len].decode("utf-8")
                pos += name_len
                accounts.append(name)
            if pos == len(data_bytes):
                return {"total_accounts": total_accounts, "accounts": accounts}
    except Exception:
        pass

    # Try to decode as conversation data:
    try:
        if len(data_bytes) >= 2:
            # First, conversation_with length (H)
            conv_len = struct.unpack("!H", data_bytes[:2])[0]
            pos = 2
            if len(data_bytes) < pos + conv_len:
                raise ValueError("Not enough data for conversation_with")
            conv_with = data_bytes[pos:pos+conv_len].decode("utf-8")
            pos += conv_len
            # Next: page_num (H), page_size (H)
            if len(data_bytes) < pos + 4:
                raise ValueError("Not enough data for paging")
            page_num, page_size = struct.unpack("!HH", data_bytes[pos:pos+4])
            pos += 4
            # Next: total_msgs (I) and remaining (I)
            if len(data_bytes) < pos + 8:
                raise ValueError("Not enough data for totals")
            total_msgs = struct.unpack("!I", data_bytes[pos:pos+4])[0]
            pos += 4
            remaining = struct.unpack("!I", data_bytes[pos:pos+4])[0]
            pos += 4
            # Next: message_count (H)
            if len(data_bytes) < pos + 2:
                raise ValueError("Not enough data for message count")
            message_count = struct.unpack("!H", data_bytes[pos:pos+2])[0]
            pos += 2
            messages = []
            for i in range(message_count):
                if len(data_bytes) < pos + 6:
                    raise ValueError("Insufficient data for a message")
                msg_id = struct.unpack("!I", data_bytes[pos:pos+4])[0]
                pos += 4
                content_len = struct.unpack("!H", data_bytes[pos:pos+2])[0]
                pos += 2
                if len(data_bytes) < pos + content_len + 1:
                    raise ValueError("Insufficient data for message content")
                content = data_bytes[pos:pos+content_len].decode("utf-8")
                pos += content_len
                read_flag = struct.unpack("!B", data_bytes[pos:pos+1])[0]
                pos += 1
                messages.append({"id": msg_id, "content": content, "read": bool(read_flag)})
            if pos == len(data_bytes):
                return {"conversation_with": conv_with, "page_num": page_num, "page_size": page_size,
                        "total_msgs": total_msgs, "remaining": remaining, "messages": messages}
    except Exception:
        pass

    # Try to decode as unread messages data:
    try:
        if len(data_bytes) >= 8:
            total_unread, remaining_unread = struct.unpack("!II", data_bytes[:8])
            pos = 8
            if len(data_bytes) < pos + 2:
                raise ValueError("Not enough data for message count")
            message_count = struct.unpack("!H", data_bytes[pos:pos+2])[0]
            pos += 2
            messages = []
            for i in range(message_count):
                if len(data_bytes) < pos + 4:
                    raise ValueError("Insufficient data for message id")
                msg_id = struct.unpack("!I", data_bytes[pos:pos+4])[0]
                pos += 4
                sender_len = struct.unpack("!H", data_bytes[pos:pos+2])[0]
                pos += 2
                if len(data_bytes) < pos + sender_len:
                    raise ValueError("Not enough data for sender")
                sender = data_bytes[pos:pos+sender_len].decode("utf-8")
                pos += sender_len
                content_len = struct.unpack("!H", data_bytes[pos:pos+2])[0]
                pos += 2
                if len(data_bytes) < pos + content_len + 1:
                    raise ValueError("Not enough data for content")
                content = data_bytes[pos:pos+content_len].decode("utf-8")
                pos += content_len
                read_flag = struct.unpack("!B", data_bytes[pos:pos+1])[0]
                pos += 1
                messages.append({"id": msg_id, "sender": sender, "content": content, "read": bool(read_flag)})
            if pos == len(data_bytes):
                return {"total_unread": total_unread, "remaining_unread": remaining_unread, "read_messages": messages}
    except Exception:
        pass

    # Fallback: return the raw data as a hex string.
    return {"raw_data": data_bytes.hex()}

def _decode_response_payload(payload: bytes) -> Dict[str, Any]:
    """
    Decode the binary response payload.
    
    Payload format:
      - success flag: 1 byte (B)
      - message length: 2 bytes (H)
      - message: message_length bytes (UTF-8)
      - data length: 2 bytes (H)
      - data: data_length bytes (binary data, decoded by decode_data_bytes)
    """
    if len(payload) < 3:
        return {}
    success_flag = payload[0]
    message_len = struct.unpack("!H", payload[1:3])[0]
    pos = 3
    message = ""
    if message_len:
        message = payload[pos:pos+message_len].decode("utf-8")
    pos += message_len
    if len(payload) < pos + 2:
        data_len = 0
    else:
        data_len = struct.unpack("!H", payload[pos:pos+2])[0]
    pos += 2
    data = None
    if data_len:
        data_bytes = payload[pos:pos+data_len]
        data = decode_data_bytes(data_bytes)
    return {
        "success": bool(success_flag),
        "message": message,
        "data": data
    }

class JSONClient:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.username: Optional[str] = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        # Queue to pass synchronous responses back to request methods.
        self.response_queue = queue.Queue()
        self.running = True
        # Start a dedicated listener thread.
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()

    def _listen(self) -> None:
        """
        Continuously listens for incoming binary data from the socket.
        Each message is prefixed by a fixed header:
          - version (B), opcode (B), payload length (H).
        The payload is then decoded using our binary response format.
        If the decoded response’s data contains an "event" key, it is handled immediately;
        otherwise, it is placed on the response queue.
        """
        buffer = b""
        header_size = struct.calcsize("!BBH")  # 1+1+2 = 4 bytes
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break  # connection closed
                buffer += data
                # Process as many complete messages as possible.
                while len(buffer) >= header_size:
                    version, opcode, payload_len = struct.unpack("!BBH", buffer[:header_size])
                    if version != VERSION:
                        raise ValueError("Protocol version mismatch")
                    if len(buffer) < header_size + payload_len:
                        break  # Wait until full payload is received.
                    payload = buffer[header_size:header_size+payload_len]
                    buffer = buffer[header_size+payload_len:]
                    response = _decode_response_payload(payload)
                    # If the decoded response's data contains an "event" key, treat it as a push event.
                    if isinstance(response.get("data"), dict) and "event" in response["data"]:
                        self.handle_push_event(response["data"])
                    else:
                        self.response_queue.put(response)
            except Exception as e:
                print("Error in listener thread:", e)
                break

    def handle_push_event(self, message: Dict[str, Any]) -> None:
        """
        Called from the listener thread when a push event arrives.
        Update your GUI (or log the event) accordingly.
        """
        event = message.get("event")
        data = message.get("data")
        if event == "NEW_MESSAGE":
            print(f"[PUSH] New message received: {data}")
        else:
            print(f"[PUSH] Unknown event received: {message}")

    def _send_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sends a request to the server using the binary protocol and waits for the corresponding response.
        """
        action = payload.get("action")
        encoder = encoder_map.get(action)
        if encoder is None:
            raise ValueError(f"Unknown action: {action}")
        data = encoder(payload)
        self.sock.sendall(data)
        # Block until a response (non-push) is available.
        response = self.response_queue.get()
        return response

    def login(self, username: str, password: str) -> str:
        payload = {
            "action": "LOGIN",
            "username": username,
            "password": password  # Note: The encoder will hash the password.
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Login failed"))
        self.username = username
        return response.get("message", "")

    def send_message(self, recipient: str, message: str) -> None:
        if not self.username:
            raise Exception("Not logged in")
        payload = {
            "action": "SEND_MESSAGE",
            "recipient": recipient,
            "message": message
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to send message"))
        print("Message sent!")

    def account_exists(self, username: str) -> bool:
        payload = {
            "action": "CHECK_USERNAME",
            "username": username
        }
        response = self._send_request(payload)
        return response.get("success", False)

    def create_account(self, username: str, password: str) -> None:
        payload = {
            "action": "CREATE_ACCOUNT",
            "username": username,
            "password": password  # Encoder will hash this.
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Account creation failed"))
        self.username = username

    def list_accounts(self, pattern: str = "*", offset: int = 0, limit: int = 10) -> List[str]:
        page_num = (offset // limit) + 1
        payload = {
            "action": "LIST_ACCOUNTS",
            "page_size": limit,
            "page_num": page_num,
            "pattern": pattern
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to list accounts"))
        accounts_data = response.get("data", {})
        accounts = accounts_data.get("accounts", [])
        if pattern and pattern != "*":
            accounts = [acct for acct in accounts if pattern in acct]
        return accounts

    def read_messages(self, offset: int = 0, count: int = 10, to_user: Optional[str] = None) -> List[Dict[str, Any]]:
        page_num = (offset // count) + 1
        payload = {
            "action": "READ_MESSAGES",
            "page_size": count,
            "page_num": page_num
        }
        if to_user:
            payload["chat_partner"] = to_user
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to read messages"))
        data = response.get("data", {})
        if to_user:
            return data.get("messages", [])
        else:
            return data.get("read_messages", [])

    def delete_message(self, message_id: int) -> None:
        payload = {
            "action": "DELETE_MESSAGE",
            "message_ids": [message_id]
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to delete message"))
        print("Message deleted.")

    def delete_account(self, username: str) -> None:
        payload = {"action": "DELETE_ACCOUNT"}
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to delete account"))
        self.username = None

    def close(self) -> None:
        self.running = False
        try:
            op_type = OP_CODES_DICT["QUIT"]
            self.sock.sendall(struct.pack("!BB", VERSION, op_type))
        except Exception:
            pass
        self.sock.close()

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()


class MockClient:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.session_token = None
        self.username: Optional[str] = None
        self.accounts = {
            "alice": "password",
            "bob": "abc",
            "natnael": "teshome",
            "michal": "kurek",
        }
        self.messages = [
            {
                "id": 1,
                "from": "alice",
                "to": "michal",
                "timestamp": 1739064990,
                "content": "hey",
            },
            {
                "id": 2,
                "from": "bob",
                "to": "michal",
                "timestamp": 1739065050,
                "content": "hello",
            },
            {
                "id": 3,
                "from": "alice",
                "to": "michal",
                "timestamp": 1739065110,
                "content": "how r u?",
            },
            {
                "id": 4,
                "from": "michal",
                "to": "alice",
                "timestamp": 1739065170,
                "content": "i'm good, u?",
            },
            {
                "id": 5,
                "from": "alice",
                "to": "michal",
                "timestamp": 1739065230,
                "content": "doing alright",
            },
            {
                "id": 6,
                "from": "bob",
                "to": "alice",
                "timestamp": 1739065290,
                "content": "nice to hear",
            },
            {
                "id": 7,
                "from": "michal",
                "to": "bob",
                "timestamp": 1739065350,
                "content": "what's up?",
            },
            {
                "id": 8,
                "from": "bob",
                "to": "michal",
                "timestamp": 1739065410,
                "content": "not much, just chilling",
            },
            {
                "id": 9,
                "from": "alice",
                "to": "bob",
                "timestamp": 1739065470,
                "content": "same here",
            },
            {
                "id": 10,
                "from": "michal",
                "to": "alice",
                "timestamp": 1739065530,
                "content": "wanna hang out later?",
            },
        ]

    def account_exists(self, username: str) -> bool:
        return username in self.accounts

    def create_account(self, username: str, password: str) -> None:
        if username in self.accounts:
            raise Exception("username taken")
        self.accounts[username] = password
        self.session_token = "dummy_token"
        self.username = username

    def delete_account(self, username: str) -> None:
        if username not in self.accounts:
            raise Exception("account does not exist")
        del self.accounts[username]

    def login(self, username: str, password: str) -> int:
        if username not in self.accounts:
            raise Exception("account does not exist")
        if self.accounts[username] != password:
            raise Exception("bad password")
        self.session_token = "dummy_token"
        self.username = username
        unread_count = len([m for m in self.messages if m["to"] == username])
        return unread_count

    def list_accounts(
        self, pattern: str = "*", offset: int = 0, limit: int = 10
    ) -> List[str]:
        accounts = list(self.accounts.keys())
        if pattern != "*" and pattern:
            accounts = [acct for acct in accounts if pattern in acct]
        return accounts[offset : offset + limit]

    def read_messages(
        self, offset: int = 0, count: int = 10, to_user: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if to_user:
            result = [
                msg
                for msg in self.messages
                if (
                    (msg["to"] == self.username and msg["from"] == to_user)
                    or (msg["from"] == self.username and msg["to"] == to_user)
                )
            ]
        else:
            result = [
                msg
                for msg in self.messages
                if msg["to"] == self.username or msg["from"] == self.username
            ]
        return result[offset : offset + count]

    def send_message(self, recipient: str, message: str) -> None:
        if not self.session_token:
            raise Exception("not logged in")
        new_msg = {
            "id": len(self.messages) + 1,
            "from": self.username if self.username else "unknown",
            "to": recipient,
            "timestamp": int(datetime.now().timestamp()),
            "content": message,
        }
        self.messages.append(new_msg)

    def delete_message(self, message_id: int) -> None:
        for msg in self.messages:
            if msg["id"] == message_id:
                self.messages.remove(msg)
                return
        raise Exception("message not found")



if __name__ == "__main__":
    import socket
    import struct
    import sys

    def recvall(sock, n):
        data = b""
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                break
            data += packet
        return data

    def send_request(sock, data):
        sock.sendall(data)
        header_size = struct.calcsize("!BBH")
        header = recvall(sock, header_size)
        if len(header) < header_size:
            raise Exception("incomplete header received")
        version, opcode, payload_len = struct.unpack("!BBH", header)
        payload = recvall(sock, payload_len)
        return _decode_response_payload(payload)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", 12345))
    print("connected to server @ localhost:12345")
    try:
        while True:
            cmd = input("cmd> ").strip().lower()
            if cmd == "login":
                username = input("username: ").strip()
                password = input("password: ").strip()
                data = encode_login({"username": username, "password": password})
                resp = send_request(s, data)
                print(resp)
            elif cmd == "create_account":
                username = input("username: ").strip()
                password = input("password: ").strip()
                data = encode_create_account({"username": username, "password": password})
                resp = send_request(s, data)
                print(resp)
            elif cmd == "delete_account":
                data = encode_delete_account()
                resp = send_request(s, data)
                print(resp)
            elif cmd == "list_accounts":
                pattern = input("pattern (default '*'): ").strip() or "*"
                offset = int(input("offset (default 0): ").strip() or "0")
                limit = int(input("limit (default 10): ").strip() or "10")
                page_num = (offset // limit) + 1
                data = encode_list_accounts({
                    "page_size": limit,
                    "page_num": page_num,
                    "pattern": pattern,
                })
                resp = send_request(s, data)
                print(resp)
            elif cmd == "send_message":
                recipient = input("recipient: ").strip()
                message = input("message: ").strip()
                data = encode_send_message({
                    "recipient": recipient,
                    "message": message,
                })
                resp = send_request(s, data)
                print(resp)
            elif cmd == "read_messages":
                offset = int(input("offset (default 0): ").strip() or "0")
                count = int(input("count (default 10): ").strip() or "10")
                partner = input("chat partner (leave blank for all): ").strip()
                payload = {"page_size": count, "page_num": (offset // count) + 1}
                if partner:
                    payload["chat_partner"] = partner
                data = encode_read_messages(payload)
                resp = send_request(s, data)
                print(resp)
            elif cmd == "delete_message":
                msg_id = int(input("message id: ").strip())
                data = encode_delete_message({"message_ids": [msg_id]})
                resp = send_request(s, data)
                print(resp)
            elif cmd == "check_username":
                username = input("username: ").strip()
                data = encode_check_username({"username": username})
                resp = send_request(s, data)
                print(resp)
            elif cmd == "quit":
                data = encode_quit()
                send_request(s, data)
                print("bye")
                break
            else:
                print("available cmds: login, create_account, delete_account, list_accounts,")
                print("send_message, read_messages, delete_message, check_username, quit")
    except Exception as e:
        print("error:", e)
    finally:
        s.close()
        sys.exit(0)
