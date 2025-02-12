import socket
import struct
import sys
import json
import threading
import queue
import hashlib
from typing import Optional, Dict, Any, List

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

# define event type codes
EVENT_NEW_MESSAGE = 0
EVENT_DELETE_MESSAGE = 1

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

def encode_delete_account(_payload) -> bytes:
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
    recipient = payload.get("to")
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
def decode_data_bytes(data_bytes: bytes, opcode=None) -> any:
    if opcode == OP_CODES_DICT["LIST_ACCOUNTS"]:
        total_accounts = struct.unpack("!I", data_bytes[:4])[0]
        account_count = struct.unpack("!H", data_bytes[4:6])[0]
        pos = 6
        accounts = []
        for i in range(account_count):
            if len(data_bytes) < pos + 2:
                raise ValueError("insufficient data for account length")
            name_len = struct.unpack("!H", data_bytes[pos:pos+2])[0]
            pos += 2
            if len(data_bytes) < pos + name_len:
                raise ValueError("insufficient data for account name")
            name = data_bytes[pos:pos+name_len].decode("utf-8")
            pos += name_len
            accounts.append(name)
        if pos == len(data_bytes):
            return {"total_accounts": total_accounts, "accounts": accounts}

    elif opcode == OP_CODES_DICT["READ_MESSAGES"]:
        if len(data_bytes) < 1:
            raise ValueError("missing flag byte in read_messages response")
        flag = struct.unpack("!B", data_bytes[:1])[0]
        payload = data_bytes[1:]
        if flag == 1:
            # conversation data
            conv_len = struct.unpack("!H", payload[:2])[0]
            pos = 2
            if len(payload) < pos + conv_len:
                raise ValueError("not enough data for conversation_with")
            conv_with = payload[pos:pos+conv_len].decode("utf-8")
            pos += conv_len
            if len(payload) < pos + 4:
                raise ValueError("not enough data for paging info")
            page_num, page_size = struct.unpack("!HH", payload[pos:pos+4])
            pos += 4
            if len(payload) < pos + 8:
                raise ValueError("not enough data for totals")
            total_msgs = struct.unpack("!I", payload[pos:pos+4])[0]
            pos += 4
            remaining = struct.unpack("!I", payload[pos:pos+4])[0]
            pos += 4
            if len(payload) < pos + 2:
                raise ValueError("not enough data for message count")
            message_count = struct.unpack("!H", payload[pos:pos+2])[0]
            pos += 2
            messages = []
            for i in range(message_count):
                if len(payload) < pos + 6:
                    raise ValueError("insufficient data for a message")
                msg_id = struct.unpack("!I", payload[pos:pos+4])[0]
                pos += 4
                content_len = struct.unpack("!H", payload[pos:pos+2])[0]
                pos += 2
                if len(payload) < pos + content_len + 1:
                    raise ValueError("insufficient data for message content")
                content = payload[pos:pos+content_len].decode("utf-8")
                pos += content_len
                read_flag = struct.unpack("!B", payload[pos:pos+1])[0]
                pos += 1
                messages.append({"id": msg_id, "content": content, "read": bool(read_flag)})
            return {"conversation_with": conv_with, "page_num": page_num,
                    "page_size": page_size, "total_msgs": total_msgs,
                    "remaining": remaining, "messages": messages}
        elif flag == 0:
            # general unread messages response
            total_unread, remaining_unread = struct.unpack("!II", payload[:8])
            pos = 8
            if len(payload) < pos + 2:
                raise ValueError("not enough data for message count")
            message_count = struct.unpack("!H", payload[pos:pos+2])[0]
            pos += 2
            messages = []
            for i in range(message_count):
                if len(payload) < pos + 4:
                    raise ValueError("insufficient data for message id")
                msg_id = struct.unpack("!I", payload[pos:pos+4])[0]
                pos += 4
                sender_len = struct.unpack("!H", payload[pos:pos+2])[0]
                pos += 2
                if len(payload) < pos + sender_len:
                    raise ValueError("not enough data for sender")
                sender = payload[pos:pos+sender_len].decode("utf-8")
                pos += sender_len
                content_len = struct.unpack("!H", payload[pos:pos+2])[0]
                pos += 2
                if len(payload) < pos + content_len + 1:
                    raise ValueError("not enough data for content")
                content = payload[pos:pos+content_len].decode("utf-8")
                pos += content_len
                read_flag = struct.unpack("!B", payload[pos:pos+1])[0]
                pos += 1
                messages.append({"id": msg_id, "from": sender, "content": content,
                                 "read": bool(read_flag)})
            return {"total_unread": total_unread, "remaining_unread": remaining_unread,
                    "read_messages": messages}
    elif opcode == OP_CODES_DICT["SEND_MESSAGE"]:
        if len(data_bytes) < 4:
            raise ValueError("insufficient data for message id")
        msg_id = struct.unpack("!I", data_bytes[:4])[0]
        return {"id": msg_id}
    else:
        # fallback to json decode.
        return json.loads(data_bytes.decode("utf-8"))

def decode_push_event(payload: bytes) -> dict:
    """
    decode a push event payload.
    expected format:
      - event type (B): 0=new_message, 1=delete_message
      - event-specific data:
          * for new_message: message_id (I), sender_len (H), sender, content_len (H), content
          * for delete_message: count (B), then count * message_id (I)
    """
    if len(payload) < 1:
        raise ValueError("empty push event payload")
    event_type = struct.unpack("!B", payload[:1])[0]
    data_bytes = payload[1:]
    if event_type == EVENT_NEW_MESSAGE:
        # new_message: id (I), sender_len (H), sender, content_len (H), content
        if len(data_bytes) < 4 + 2:
            raise ValueError("insufficient data for new_message event")
        msg_id = struct.unpack("!I", data_bytes[:4])[0]
        pos = 4
        sender_len = struct.unpack("!H", data_bytes[pos:pos+2])[0]
        pos += 2
        if len(data_bytes) < pos + sender_len + 2:
            raise ValueError("insufficient data for sender in new_message event")
        sender = data_bytes[pos:pos+sender_len].decode("utf-8")
        pos += sender_len
        content_len = struct.unpack("!H", data_bytes[pos:pos+2])[0]
        pos += 2
        if len(data_bytes) < pos + content_len:
            raise ValueError("insufficient data for content in new_message event")
        content = data_bytes[pos:pos+content_len].decode("utf-8")
        return {"event": "NEW_MESSAGE", "data": {"id": msg_id, "from": sender, "content": content}}
    elif event_type == EVENT_DELETE_MESSAGE:
        # delete_message: count (B) then count * message_id (I)
        if len(data_bytes) < 1:
            raise ValueError("insufficient data for delete_message event")
        count = struct.unpack("!B", data_bytes[:1])[0]
        pos = 1
        message_ids = []
        for _ in range(count):
            if len(data_bytes) < pos + 4:
                raise ValueError("insufficient data for a message id in delete_message event")
            msg_id = struct.unpack("!I", data_bytes[pos:pos+4])[0]
            pos += 4
            message_ids.append(msg_id)
        return {"event": "DELETE_MESSAGE", "data": {"message_ids": message_ids}}
    else:
        raise ValueError(f"unknown push event type: {event_type}")

def _decode_response_payload(payload: bytes, opcode=None) -> Dict[str, Any]:
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
        data = decode_data_bytes(data_bytes, opcode)
    return {
        "success": bool(success_flag),
        "message": message,
        "data": data
    }

class CustomProtocolClient:
    def __init__(self, host: str, port: int,
                 on_msg_callback = None,
                 on_delete_callback = None) -> None:
        self.host = host
        self.port = port
        self.username: Optional[str] = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.response_queue = queue.Queue()
        self.on_msg_callback = on_msg_callback
        self.on_delete_callback = on_delete_callback
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()

    def _listen(self) -> None:
        buffer = b""
        header_size = struct.calcsize("!BBH")  # version (B), opcode (B), payload_len (H)
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break  # connection closed
                buffer += data
                while len(buffer) >= header_size:
                    version, opcode, payload_len = struct.unpack("!BBH", buffer[:header_size])
                    if version != VERSION:
                        raise ValueError("protocol version mismatch")
                    if len(buffer) < header_size + payload_len:
                        break  # wait for full payload
                    payload = buffer[header_size : header_size + payload_len]
                    buffer = buffer[header_size + payload_len :]
                    if opcode == 0:
                        # push event
                        event = decode_push_event(payload)
                        self.handle_push_event(event)
                    else:
                        response = _decode_response_payload(payload, opcode)
                        self.response_queue.put(response)
            except Exception as e:
                print("Error in listener thread:", e)
                break

    def handle_push_event(self, message: Dict[str, Any]) -> None:
        event = message.get("event")
        data = message.get("data")
        if event == "NEW_MESSAGE":
            print(f"[PUSH] New message received: {data}")
            if self.on_msg_callback:
                self.on_msg_callback(data)
        elif event == "DELETE_MESSAGE":
            print(f"[PUSH] Delete message event: {data}")
            if self.on_delete_callback:
                self.on_delete_callback(data)
        else:
            print(f"[PUSH] Unknown push event: {message}")

    def _send_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        action = payload.get("action")
        encoder = encoder_map.get(action)
        if not encoder:
            raise ValueError(f"unknown action: {action}")
        data = encoder(payload)
        self.sock.sendall(data)
        response = self.response_queue.get()
        return response

    # -- Public API methods --
    def login(self, username: str, password: str) -> str:
        payload = {"action": "LOGIN", "username": username, "password": password}
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Login failed"))
        self.username = username
        return response.get("message", "")

    def create_account(self, username: str, password: str) -> None:
        payload = {"action": "CREATE_ACCOUNT", "username": username, "password": password}
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Account creation failed"))
        self.username = username

    def delete_account(self) -> None:
        payload = {"action": "DELETE_ACCOUNT"}
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Delete account failed"))
        self.username = None

    def list_accounts(self, pattern: str = "*", offset: int = 0, limit: int = 10) -> List[str]:
        page_num = (offset // limit) + 1
        payload = {"action": "LIST_ACCOUNTS", "page_size": limit, "page_num": page_num, "pattern": pattern}
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "List accounts failed"))
        accounts_data = response.get("data", {})
        return accounts_data.get("accounts", [])

    def send_message(self, recipient: str, message: str) -> int:
        if not self.username:
            raise Exception("not logged in")
        payload = {"action": "SEND_MESSAGE", "to": recipient, "message": message}
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to send message"))
        id = response.get("data", {}).get("id", -1)
        print(f"Message sent! Got ID: {id}")
        return id

    def read_messages(self, offset: int = 0, count: int = 10, to_user: Optional[str] = None
                      ) -> List[Dict[str, Any]]:
        page_num = (offset // count) + 1
        payload = {"action": "READ_MESSAGES", "page_size": count, "page_num": page_num}
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
        payload = {"action": "DELETE_MESSAGE", "message_ids": [message_id]}
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to delete message"))
        print("Message deleted.")

    def account_exists(self, username: str) -> bool:
        payload = {"action": "CHECK_USERNAME", "username": username}
        response = self._send_request(payload)
        return response.get("success", False)

    def close(self) -> None:
        self.running = False
        try:
            data = encode_quit({})
            self.sock.sendall(data)
        except Exception:
            pass
        self.sock.close()


if __name__ == "__main__":
    """For testing purposes only!"""
    client = CustomProtocolClient("localhost", 12345)
    try:
        while True:
            cmd = input("cmd> ").strip().lower()
            if cmd == "login":
                username = input("username: ").strip()
                password = input("password: ").strip()
                print(client.login(username, password))
            elif cmd == "create_account":
                username = input("username: ").strip()
                password = input("password: ").strip()
                client.create_account(username, password)
                print("account created!")
            elif cmd == "delete_account":
                client.delete_account()
                print("account deleted!")
            elif cmd == "list_accounts":
                pattern = input("pattern (default '*'): ").strip() or "*"
                offset = int(input("offset (default 0): ").strip() or "0")
                limit = int(input("limit (default 10): ").strip() or "10")
                accounts = client.list_accounts(pattern, offset, limit)
                print("accounts:", accounts)
            elif cmd == "send_message":
                recipient = input("recipient: ").strip()
                message = input("message: ").strip()
                client.send_message(recipient, message)
            elif cmd == "read_messages":
                offset = int(input("offset (default 0): ").strip() or "0")
                count = int(input("count (default 10): ").strip() or "10")
                partner = input("chat partner (leave blank for all): ").strip()
                msgs = client.read_messages(offset, count, partner if partner else None)
                print("messages:", msgs)
            elif cmd == "delete_message":
                msg_id = int(input("message id: ").strip() or "-1")
                client.delete_message(msg_id)
            elif cmd == "check_username":
                username = input("username: ").strip()
                exists = client.account_exists(username)
                print(f"username {'exists' if exists else 'does not exist'}")
            elif cmd == "quit":
                client.close()
                print("bye")
                break
            else:
                print("available cmds: login, create_account, delete_account, list_accounts,")
                print("send_message, read_messages, delete_message, check_username, quit")
    except Exception as e:
        print("error:", e)
    finally:
        client.close()
