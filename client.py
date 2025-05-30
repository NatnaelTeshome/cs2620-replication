import socket
import json
import threading
import queue
import hashlib
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime


class JSONClient:
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
        # Queue to pass synchronous responses back to request methods.
        self.response_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.running: bool = True
        # Callback functions (optional)
        self.on_msg_callback: Optional[
            Callable[[Dict[str, Any]], None]
        ] = on_msg_callback
        self.on_delete_callback: Optional[
            Callable[[Dict[str, Any]], None]
        ] = on_delete_callback

        # Start a dedicated listener thread.
        self.listener_thread: threading.Thread = threading.Thread(
            target=self._listen, daemon=True
        )
        self.listener_thread.start()

    def _listen(self) -> None:
        """
        Continuously listens for incoming data on the socket.
        Push events (which contain an 'event' key) are handled immediately.
        All other messages are placed on the response queue.
        """
        buffer: str = ""
        while self.running:
            try:
                data: bytes = self.sock.recv(4096)
                if not data:
                    break  # connection closed
                buffer += data.decode("utf-8")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        try:
                            message: Dict[str, Any] = json.loads(line.strip())
                        except json.JSONDecodeError:
                            continue  # Skip invalid JSON
                        # Check for a push event.
                        if "event" in message:
                            self.handle_push_event(message)
                        else:
                            # Otherwise, this is the reply to a request.
                            self.response_queue.put(message)
            except Exception as e:
                print("Error in listener thread:", e)
                break

    def handle_push_event(self, message: Dict[str, Any]) -> None:
        """
        Called from the listener thread when a push event arrives.
        Update your GUI (or log the event) accordingly.
        """
        event: Any = message.get("event")
        data: Any = message.get("data")
        if event == "NEW_MESSAGE":
            print(f"[PUSH] New message received: {data}")
            if self.on_msg_callback:
                self.on_msg_callback(data)
        elif event == "DELETE_MESSAGE":
            print(f"[PUSH] Message deletion request received: {data}")
            if self.on_delete_callback:
                self.on_delete_callback(data)
        else:
            print(f"[PUSH] Unknown event received: {message}")

    def _send_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sends a JSON request to the server and waits for the corresponding response.
        Any asynchronous push events are handled by the listener.
        """
        data: str = json.dumps(payload) + "\n"
        self.sock.sendall(data.encode("utf-8"))
        # Block until a response (non-push) is available.
        response: Dict[str, Any] = self.response_queue.get()
        return response

    def login(self, username: str, password: str) -> str:
        payload: Dict[str, Any] = {
            "action": "LOGIN",
            "username": username,
            "password_hash": self._hash_password(password),
        }
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Login failed"))
        self.username = username
        return response.get("message", "")

    def send_message(self, recipient: str, message: str) -> int:
        """Sends message to specified recipient.
        On success, returns message id assigned by server, or -1 on failure."""
        if not self.username:
            raise Exception("Not logged in")
        payload: Dict[str, Any] = {
            "action": "SEND",
            "to": recipient,
            "content": message,
        }
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to send message"))
        # Get the id from response data; default to -1 if not found.
        msg_id: int = response.get("data", {}).get("id", -1)  # type: ignore
        print(f"Message sent! Got ID: {msg_id}")
        return msg_id

    def account_exists(self, username: str) -> bool:
        payload: Dict[str, Any] = {
            "action": "USERNAME",
            "username": username,
        }
        response: Dict[str, Any] = self._send_request(payload)
        return response.get("success", False)

    def create_account(self, username: str, password: str) -> None:
        payload: Dict[str, Any] = {
            "action": "CREATE",
            "username": username,
            "password_hash": self._hash_password(password),
        }
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Account creation failed"))
        self.username = username

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
            raise Exception(response.get("message", "Failed to list accounts"))
        accounts_data: Dict[str, Any] = response.get("data", {})
        accounts: List[str] = accounts_data.get("accounts", [])
        return accounts

    def read_messages(
        self, offset: int = 0, count: int = 10, to_user: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        page_num: int = (offset // count) + 1
        payload: Dict[str, Any] = {
            "action": "READ",
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
        print("Message deleted.")

    def delete_account(self, username: str) -> None:
        payload: Dict[str, Any] = {"action": "DELETE_ACCOUNT"}
        response: Dict[str, Any] = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "Failed to delete account"))
        self.username = None

    def close(self) -> None:
        self.running = False
        try:
            payload: Dict[str, Any] = {"action": "QUIT"}
            self.sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        except Exception:
            pass
        self.sock.close()

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()


class MockClient:
    def __init__(self, host: str, port: int) -> None:
        self.host: str = host
        self.port: int = port
        self.session_token: Optional[str] = None
        self.username: Optional[str] = None
        self.accounts: Dict[str, str] = {
            "alice": "password",
            "bob": "abc",
            "natnael": "teshome",
            "michal": "kurek",
        }
        self.messages: List[Dict[str, Any]] = [
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
        unread_count: int = len([m for m in self.messages if m["to"] == username])
        return unread_count

    def list_accounts(
        self, pattern: str = "*", offset: int = 0, limit: int = 10
    ) -> List[str]:
        accounts_list: List[str] = list(self.accounts.keys())
        if pattern != "*" and pattern:
            accounts_list = [acct for acct in accounts_list if pattern in acct]
        return accounts_list[offset : offset + limit]

    def read_messages(
        self, offset: int = 0, count: int = 10, to_user: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if to_user:
            result: List[Dict[str, Any]] = [
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
        new_msg: Dict[str, Any] = {
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
