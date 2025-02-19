import socket
import struct
import json
import threading
import queue
import hashlib
import logging
from typing import Optional, Dict, Any, List, Callable

VERSION: int = 1

OP_CODES_DICT: Dict[str, int] = {
    "LOGIN": 1,
    "CREATE_ACCOUNT": 2,
    "DELETE_ACCOUNT": 3,
    "LIST_ACCOUNTS": 4,
    "SEND_MESSAGE": 5,
    "READ_MESSAGES": 6,
    "DELETE_MESSAGE": 7,
    "CHECK_USERNAME": 8,
    "QUIT": 9,
}

# define event type codes
EVENT_NEW_MESSAGE: int = 0
EVENT_DELETE_MESSAGE: int = 1


def encode_login(payload: Dict[str, Any]) -> bytes:
    op_code: int = OP_CODES_DICT["LOGIN"]
    username: str = payload.get("username", "")
    password: str = payload.get("password", "")
    username_bytes: bytes = username.encode("utf-8")
    password_hash: str = hashlib.sha256(password.encode("utf-8")).hexdigest()
    password_bytes: bytes = password_hash.encode("utf-8")
    # Format: Version (B), Opcode (B), username length (H), username, password length (H), password_hash
    fmt: str = f"!BBH{len(username_bytes)}sH{len(password_bytes)}s"
    return struct.pack(
        fmt,
        VERSION,
        op_code,
        len(username_bytes),
        username_bytes,
        len(password_bytes),
        password_bytes,
    )


def encode_create_account(payload: Dict[str, Any]) -> bytes:
    op_code: int = OP_CODES_DICT["CREATE_ACCOUNT"]
    username: str = payload.get("username", "")
    password: str = payload.get("password", "")
    username_bytes: bytes = username.encode("utf-8")
    password_hash: str = hashlib.sha256(password.encode("utf-8")).hexdigest()
    password_bytes: bytes = password_hash.encode("utf-8")
    # Same format as LOGIN.
    fmt: str = f"!BBH{len(username_bytes)}sH{len(password_bytes)}s"
    return struct.pack(
        fmt,
        VERSION,
        op_code,
        len(username_bytes),
        username_bytes,
        len(password_bytes),
        password_bytes,
    )


def encode_delete_account(_payload: Dict[str, Any]) -> bytes:
    op_code: int = OP_CODES_DICT["DELETE_ACCOUNT"]
    # No additional payload.
    return struct.pack("!BB", VERSION, op_code)


def encode_list_accounts(payload: Dict[str, Any]) -> bytes:
    op_code: int = OP_CODES_DICT["LIST_ACCOUNTS"]
    page_size: int = payload.get("page_size", -1)
    page_num: int = payload.get("page_num", -1)
    pattern: str = payload.get("pattern", "")
    pattern_bytes: bytes = pattern.encode("utf-8")
    # Format: Version (B), Opcode (B), page_size (H), page_num (H), pattern length (H), pattern_bytes
    return struct.pack(
        f"!BBHHH{len(pattern_bytes)}s",
        VERSION,
        op_code,
        page_size,
        page_num,
        len(pattern_bytes),
        pattern_bytes,
    )


def encode_send_message(payload: Dict[str, Any]) -> bytes:
    op_code: int = OP_CODES_DICT["SEND_MESSAGE"]
    recipient: str = payload.get("to", "")
    message: str = payload.get("message", "")
    recipient_bytes: bytes = recipient.encode("utf-8")
    message_bytes: bytes = message.encode("utf-8")
    # Format: Version (B), Opcode (B), recipient length (H), recipient, message length (H), message
    fmt: str = f"!BBH{len(recipient_bytes)}sH{len(message_bytes)}s"
    return struct.pack(
        fmt,
        VERSION,
        op_code,
        len(recipient_bytes),
        recipient_bytes,
        len(message_bytes),
        message_bytes,
    )


def encode_read_messages(payload: Dict[str, Any]) -> bytes:
    op_code: int = OP_CODES_DICT["READ_MESSAGES"]
    page_size: int = payload.get("page_size", -1)
    page_num: int = payload.get("page_num", -1)
    chat_partner: Optional[str] = payload.get("chat_partner", None)
    # Base: Version (B), Opcode (B), page_size (H), page_num (H)
    base: bytes = struct.pack("!BBHH", VERSION, op_code, page_size, page_num)
    if chat_partner:
        partner_bytes: bytes = chat_partner.encode("utf-8")
        # Flag (B) = 1 indicates partner provided, then partner length (H) and partner bytes.
        fmt: str = f"!BH{len(partner_bytes)}s"
        return base + struct.pack(fmt, 1, len(partner_bytes), partner_bytes)
    else:
        # Flag (B) = 0 indicates no chat partner.
        return base + struct.pack("!B", 0)


def encode_delete_message(payload: Dict[str, Any]) -> bytes:
    op_code: int = OP_CODES_DICT["DELETE_MESSAGE"]
    message_ids: List[int] = payload.get("message_ids", [])
    count: int = len(message_ids)
    # Format: Version (B), Opcode (B), count (B), then each message id as unsigned int (I)
    fmt: str = f"!BBB{count}I"
    return struct.pack(fmt, VERSION, op_code, count, *message_ids)


def encode_check_username(payload: Dict[str, Any]) -> bytes:
    op_code: int = OP_CODES_DICT["CHECK_USERNAME"]
    username: str = payload.get("username", "")
    username_bytes: bytes = username.encode("utf-8")
    # Format: Version (B), Opcode (B), username length (H), username
    fmt: str = f"!BBH{len(username_bytes)}s"
    return struct.pack(fmt, VERSION, op_code, len(username_bytes), username_bytes)


def encode_quit() -> bytes:
    op_code: int = OP_CODES_DICT["QUIT"]
    return struct.pack("!BB", VERSION, op_code)


# Map actions to their encoder functions.
encoder_map: Dict[str, Callable[..., bytes]] = {
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
# ---------------------------------------------------------------------------
def decode_data_bytes(data_bytes: bytes, opcode: Optional[int] = None) -> Any:
    pos: int = 0
    if opcode == OP_CODES_DICT["LIST_ACCOUNTS"]:
        total_accounts: int = struct.unpack("!I", data_bytes[:4])[0]
        account_count: int = struct.unpack("!H", data_bytes[4:6])[0]
        pos += 6
        accounts_list: List[str] = []
        for i in range(account_count):
            if len(data_bytes) < pos + 2:
                raise ValueError("insufficient data for account length")
            name_len: int = struct.unpack("!H", data_bytes[pos : pos + 2])[0]
            pos += 2
            if len(data_bytes) < pos + name_len:
                raise ValueError("insufficient data for account name")
            name: str = data_bytes[pos : pos + name_len].decode("utf-8")
            pos += name_len
            accounts_list.append(name)
        if pos == len(data_bytes):
            return {"total_accounts": total_accounts, "accounts": accounts_list}

    elif opcode == OP_CODES_DICT["READ_MESSAGES"]:
        if len(data_bytes) < 1:
            raise ValueError("missing flag byte in read_messages response")
        flag: int = struct.unpack("!B", data_bytes[:1])[0]
        payload: bytes = data_bytes[1:]
        messages: List[Dict[str, Any]] = []
        msg_id: int = -1
        message_count: int = 0
        content: str = ""
        content_len: int = 0
        read_flag: int = 0
        timestamp: int = 0
        if flag == 1:
            # Conversation data.
            conv_len: int = struct.unpack("!H", payload[:2])[0]
            pos += 2
            if len(payload) < pos + conv_len:
                raise ValueError("not enough data for conversation_with")
            conv_with: str = payload[pos : pos + conv_len].decode("utf-8")
            pos += conv_len
            if len(payload) < pos + 4:
                raise ValueError("not enough data for paging info")
            page_num, page_size = struct.unpack("!HH", payload[pos : pos + 4])
            pos += 4
            if len(payload) < pos + 8:
                raise ValueError("not enough data for totals")
            total_msgs: int = struct.unpack("!I", payload[pos : pos + 4])[0]
            pos += 4
            remaining: int = struct.unpack("!I", payload[pos : pos + 4])[0]
            pos += 4
            if len(payload) < pos + 2:
                raise ValueError("not enough data for message count")
            message_count = struct.unpack("!H", payload[pos : pos + 2])[0]
            pos += 2
            for i in range(message_count):
                if len(payload) < pos + 6:
                    raise ValueError("insufficient data for a message")
                msg_id = struct.unpack("!I", payload[pos : pos + 4])[0]
                pos += 4
                content_len = struct.unpack("!H", payload[pos : pos + 2])[0]
                pos += 2
                if len(payload) < pos + content_len + 1:
                    raise ValueError("insufficient data for message content")
                content = payload[pos : pos + content_len].decode("utf-8")
                pos += content_len
                read_flag = struct.unpack("!B", payload[pos : pos + 1])[0]
                pos += 1
                if len(payload) < pos + 4:
                    raise ValueError("insufficient data for timestamp")
                timestamp = struct.unpack("!I", payload[pos : pos + 4])[0]
                pos += 4
                messages.append(
                    {
                        "id": msg_id,
                        "content": content,
                        "read": bool(read_flag),
                        "timestamp": timestamp,
                    }
                )
            return {
                "conversation_with": conv_with,
                "page_num": page_num,
                "page_size": page_size,
                "total_msgs": total_msgs,
                "remaining": remaining,
                "messages": messages,
            }
        elif flag == 0:
            # General unread messages.
            total_unread, remaining_unread = struct.unpack("!II", payload[:8])
            pos += 8
            if len(payload) < pos + 2:
                raise ValueError("not enough data for message count")
            message_count = struct.unpack("!H", payload[pos : pos + 2])[0]
            pos += 2
            for i in range(message_count):
                if len(payload) < pos + 4:
                    raise ValueError("insufficient data for message id")
                msg_id = struct.unpack("!I", payload[pos : pos + 4])[0]
                pos += 4
                sender_len: int = struct.unpack("!H", payload[pos : pos + 2])[0]
                pos += 2
                if len(payload) < pos + sender_len:
                    raise ValueError("not enough data for sender")
                sender: str = payload[pos : pos + sender_len].decode("utf-8")
                pos += sender_len
                content_len = struct.unpack("!H", payload[pos : pos + 2])[0]
                pos += 2
                if len(payload) < pos + content_len + 1:
                    raise ValueError("not enough data for content")
                content = payload[pos : pos + content_len].decode("utf-8")
                pos += content_len
                read_flag = struct.unpack("!B", payload[pos : pos + 1])[0]
                pos += 1
                if len(payload) < pos + 4:
                    raise ValueError("insufficient data for timestamp")
                timestamp = struct.unpack("!I", payload[pos : pos + 4])[0]
                pos += 4
                messages.append(
                    {
                        "id": msg_id,
                        "from": sender,
                        "content": content,
                        "read": bool(read_flag),
                        "timestamp": timestamp,
                    }
                )
            return {
                "total_unread": total_unread,
                "remaining_unread": remaining_unread,
                "read_messages": messages,
            }
    elif opcode == OP_CODES_DICT["SEND_MESSAGE"]:
        if len(data_bytes) < 4:
            raise ValueError("insufficient data for message id")
        msg_id = struct.unpack("!I", data_bytes[:4])[0]
        return {"id": msg_id}
    else:
        # Fallback: assume JSON.
        return json.loads(data_bytes.decode("utf-8"))


def decode_push_event(payload: bytes) -> Dict[str, Any]:
    """
    Decode a push event payload.
    Expected format:
      - event type (B): 0=new_message, 1=delete_message
      - event-specific data.
    """
    if len(payload) < 1:
        raise ValueError("empty push event payload")
    pos: int = 0
    msg_id: int = 0
    event_type: int = struct.unpack("!B", payload[:1])[0]
    data_bytes: bytes = payload[1:]
    if event_type == EVENT_NEW_MESSAGE:
        if len(data_bytes) < 4 + 2:
            raise ValueError("insufficient data for new_message event")
        msg_id = struct.unpack("!I", data_bytes[:4])[0]
        pos += 4
        sender_len: int = struct.unpack("!H", data_bytes[pos : pos + 2])[0]
        pos += 2
        if len(data_bytes) < pos + sender_len + 2:
            raise ValueError("insufficient data for sender in new_message event")
        sender: str = data_bytes[pos : pos + sender_len].decode("utf-8")
        pos += sender_len
        content_len: int = struct.unpack("!H", data_bytes[pos : pos + 2])[0]
        pos += 2
        if len(data_bytes) < pos + content_len:
            raise ValueError("insufficient data for content in new_message event")
        content: str = data_bytes[pos : pos + content_len].decode("utf-8")
        pos += content_len
        if len(data_bytes) < pos + 4:
            raise ValueError("insufficient data for timestamp in new_message event")
        timestamp: int = struct.unpack("!I", data_bytes[pos : pos + 4])[0]
        return {
            "event": "NEW_MESSAGE",
            "data": {
                "id": msg_id,
                "from": sender,
                "content": content,
                "timestamp": timestamp,
            },
        }
    elif event_type == EVENT_DELETE_MESSAGE:
        if len(data_bytes) < 1:
            raise ValueError("insufficient data for delete_message event")
        count: int = struct.unpack("!B", data_bytes[:1])[0]
        pos += 1
        message_ids: List[int] = []
        for _ in range(count):
            if len(data_bytes) < pos + 4:
                raise ValueError(
                    "insufficient data for a message id in delete_message event"
                )
            msg_id = struct.unpack("!I", data_bytes[pos : pos + 4])[0]
            pos += 4
            message_ids.append(msg_id)
        return {"event": "DELETE_MESSAGE", "data": {"message_ids": message_ids}}
    else:
        raise ValueError(f"unknown push event type: {event_type}")


def _decode_response_payload(
    payload: bytes, opcode: Optional[int] = None
) -> Dict[str, Any]:
    """
    Decode the binary response payload.

    Payload format:
      - success flag: 1 byte (B)
      - message length: 2 bytes (H)
      - message: message_length bytes (UTF-8)
      - data length: 2 bytes (H)
      - data: data_length bytes
    """
    if len(payload) < 3:
        return {}
    success_flag: int = payload[0]
    message_len: int = struct.unpack("!H", payload[1:3])[0]
    pos: int = 3
    message: str = ""
    if message_len:
        message = payload[pos : pos + message_len].decode("utf-8")
    pos += message_len
    data_len: int = 0
    if len(payload) >= pos + 2:
        data_len = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2
    data: Optional[Any] = None
    if data_len:
        data_bytes: bytes = payload[pos : pos + data_len]
        data = decode_data_bytes(data_bytes, opcode)
    return {"success": bool(success_flag), "message": message, "data": data}


class CustomProtocolClient:
    def __init__(
        self,
        host: str,
        port: int,
        on_msg_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_delete_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.username: Optional[str] = None
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.response_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.on_msg_callback: Optional[
            Callable[[Dict[str, Any]], None]
        ] = on_msg_callback
        self.on_delete_callback: Optional[
            Callable[[Dict[str, Any]], None]
        ] = on_delete_callback
        self.running: bool = True
        self.listener_thread: threading.Thread = threading.Thread(
            target=self._listen, daemon=True
        )
        self.listener_thread.start()

    def _listen(self) -> None:
        buffer: bytes = b""
        header_size: int = struct.calcsize("!BBH")  # version, opcode, payload_len
        while self.running:
            try:
                data: bytes = self.sock.recv(4096)
                if not data:
                    break  # connection closed
                buffer += data
                while len(buffer) >= header_size:
                    version, opcode, payload_len = struct.unpack(
                        "!BBH", buffer[:header_size]
                    )
                    if version != VERSION:
                        raise ValueError("protocol version mismatch")
                    if len(buffer) < header_size + payload_len:
                        break  # wait for full payload
                    payload: bytes = buffer[header_size : header_size + payload_len]
                    buffer = buffer[header_size + payload_len :]
                    if opcode == 0:
                        # Push event.
                        event: Dict[str, Any] = decode_push_event(payload)
                        self.handle_push_event(event)
                    else:
                        response: Dict[str, Any] = _decode_response_payload(
                            payload, opcode
                        )
                        self.response_queue.put(response)
            except Exception as e:
                logging.error("Error in listener thread:", e)
                break

    def handle_push_event(self, message: Dict[str, Any]) -> None:
        event: str = message.get("event", "No Event Field")
        data: dict[str, Any] = message.get("data", "No Data Field")
        if event == "NEW_MESSAGE":
            logging.debug(f"[PUSH] New message received: {data}")
            if self.on_msg_callback:
                self.on_msg_callback(data)
        elif event == "DELETE_MESSAGE":
            logging.debug(f"[PUSH] Delete message event: {data}")
            if self.on_delete_callback:
                self.on_delete_callback(data)
        else:
            logging.debug(f"[PUSH] Unknown push event: {message}")

    def _send_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        action: str = payload.get("action", "")
        encoder = encoder_map.get(action)
        if not encoder:
            raise ValueError(f"unknown action: {action}")
        data: bytes = encoder(payload)
        self.sock.sendall(data)
        response: Dict[str, Any] = self.response_queue.get()
        return response

    # -- Public API methods --
    def login(self, username: str, password: str) -> str:
        payload: Dict[str, Any] = {
            "action": "LOGIN",
            "username": username,
            "password": password,
        }
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Login failed"))
        self.username = username
        return response.get("message", "")

    def create_account(self, username: str, password: str) -> None:
        payload: Dict[str, Any] = {
            "action": "CREATE_ACCOUNT",
            "username": username,
            "password": password,
        }
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Account creation failed"))
        self.username = username

    def delete_account(self, _payload: Optional[Any] = None) -> None:
        payload: Dict[str, Any] = {"action": "DELETE_ACCOUNT"}
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Delete account failed"))
        self.username = None

    def list_accounts(
        self, pattern: str = "*", offset: int = 0, limit: int = 10
    ) -> List[str]:
        page_num: int = (offset // limit) + 1
        payload: Dict[str, Any] = {
            "action": "LIST_ACCOUNTS",
            "page_size": limit,
            "page_num": page_num,
            "pattern": pattern,
        }
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "List accounts failed"))
        accounts_data: Dict[str, Any] = response.get("data", {})
        return accounts_data.get("accounts", [])

    def send_message(self, recipient: str, message: str) -> int:
        if not self.username:
            raise Exception("not logged in")
        payload: Dict[str, Any] = {
            "action": "SEND_MESSAGE",
            "to": recipient,
            "message": message,
        }
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to send message"))
        msg_id: int = response.get("data", {}).get("id", -1)
        logging.debug(f"Message sent! Got ID: {msg_id}")
        return msg_id

    def read_messages(
        self, offset: int = 0, count: int = 10, to_user: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        page_num: int = (offset // count) + 1
        payload: Dict[str, Any] = {
            "action": "READ_MESSAGES",
            "page_size": count,
            "page_num": page_num,
        }
        if to_user:
            payload["chat_partner"] = to_user
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to read messages"))
        data: Dict[str, Any] = response.get("data", {})
        if to_user:
            return data.get("messages", [])
        else:
            return data.get("read_messages", [])

    def delete_message(self, message_id: int) -> None:
        payload: Dict[str, Any] = {
            "action": "DELETE_MESSAGE",
            "message_ids": [message_id],
        }
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to delete message"))
        logging.debug("Message deleted.")

    def account_exists(self, username: str) -> bool:
        payload: Dict[str, Any] = {"action": "CHECK_USERNAME", "username": username}
        response: Dict[str, Any] = self._send_request(payload)
        return response.get("success", False)

    def close(self) -> None:
        self.running = False
        try:
            data: bytes = encode_quit()
            self.sock.sendall(data)
        except Exception:
            pass
        self.sock.close()


if __name__ == "__main__":
    """For testing purposes only!"""
    client: CustomProtocolClient = CustomProtocolClient("localhost", 12345)
    try:
        while True:
            cmd: str = input("cmd> ").strip().lower()
            if cmd == "login":
                username: str = input("username: ").strip()
                password: str = input("password: ").strip()
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
                pattern: str = input("pattern (default '*'): ").strip() or "*"
                offset: int = int(input("offset (default 0): ").strip() or "0")
                limit: int = int(input("limit (default 10): ").strip() or "10")
                accounts: List[str] = client.list_accounts(pattern, offset, limit)
                print("accounts:", accounts)
            elif cmd == "send_message":
                recipient: str = input("recipient: ").strip()
                message: str = input("message: ").strip()
                client.send_message(recipient, message)
            elif cmd == "read_messages":
                offset = int(input("offset (default 0): ").strip() or "0")
                count = int(input("count (default 10): ").strip() or "10")
                partner: str = input("chat partner (leave blank for all): ").strip()
                msgs: List[Dict[str, Any]] = client.read_messages(
                    offset, count, partner if partner else None
                )
                print("messages:", msgs)
            elif cmd == "delete_message":
                msg_id: int = int(input("message id: ").strip() or "-1")
                client.delete_message(msg_id)
            elif cmd == "check_username":
                username = input("username: ").strip()
                exists: bool = client.account_exists(username)
                print(f"username {'exists' if exists else 'does not exist'}")
            elif cmd == "quit":
                client.close()
                print("bye")
                break
            else:
                print(
                    "available cmds: login, create_account, delete_account, list_accounts,"
                )
                print(
                    "send_message, read_messages, delete_message, check_username, quit"
                )
    except Exception as e:
        print("error:", e)
    finally:
        client.close()
