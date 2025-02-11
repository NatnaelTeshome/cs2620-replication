from abc import ABC, abstractmethod
import socket
import threading
import json
import struct
from queue import Queue
from typing import Optional

import socket
import json
import hashlib
from typing import List, Optional, Dict, Any


class JSONClient:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.session_token: Optional[str] = None
        self.username: Optional[str] = None
        # establish a persistent connection
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

    def _send_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # add session_token if available
        if self.session_token:
            payload["session_token"] = self.session_token
        data = json.dumps(payload) + "\n"
        self.sock.sendall(data.encode('utf-8'))
        # we assume server response fits in a single recv; for larger responses adapt accordingly
        response_data = self.sock.recv(4096).decode('utf-8').strip()
        try:
            response = json.loads(response_data)
        except json.JSONDecodeError:
            response = {"success": False, "message": "Invalid response from server."}
        return response

    def account_exists(self, username: str) -> bool:
        # TODO: Get this fixed (Nati)
        return False
        # use LIST_ACCOUNTS to check if username exists
        payload = {
            "action": "LIST_ACCOUNTS",
            "page_size": 100,
            "page_num": 1
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "failed to list accounts"))
        accounts = response.get("data", [])
        return username in accounts

    def create_account(self, username: str, password: str) -> None:
        payload = {
            "action": "CREATE",
            "username": username,
            "password_hash": self._hash_password(password)
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "account creation failed"))

    def delete_account(self, username: str) -> None:
        payload = {
            "action": "DELETE_ACCOUNT"
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "failed to delete account"))

    def login(self, username: str, password: str) -> int:
        payload = {
            "action": "LOGIN",
            "username": username,
            "password_hash": self._hash_password(password)
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "login failed"))
        self.session_token = response.get("data", {}).get("session_token")
        self.username = username
        # assuming the server returns an unread count; otherwise adjust accordingly
        unread = response.get("data", {}).get("unread", 0)
        return unread

    def list_accounts(self, pattern: str = "*", offset: int = 0, limit: int = 10) -> List[str]:
        # assuming server's LIST_ACCOUNTS supports pagination only via page_size and page_num
        page_num = (offset // limit) + 1
        payload = {
            "action": "LIST_ACCOUNTS",
            "page_size": limit,
            "page_num": page_num
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "failed to list accounts"))
        accounts_info = response.get("data", {})
        print(f"fetched {accounts_info.get('total_accounts', 0)} accounts")
        accounts = []
        if pattern != "*" and pattern:
            accounts = [acct for acct in accounts_info.get("accounts", []) if pattern in acct]
        return accounts

    def read_messages(self, offset: int = 0, count: int = 10,
                      to_user: Optional[str] = None) -> List[Dict[str, Any]]:
        payload = {
            "action": "READ",
            "count": count
        }
        # optionally, include recipient to filter conversation
        if to_user:
            payload["to_user"] = to_user
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "failed to read messages"))
        messages = response.get("data", [])
        # simulate pagination locally if needed
        return messages[offset: offset + count]

    def send_message(self, recipient: str, message: str) -> None:
        if not self.session_token:
            raise Exception("not logged in")
        payload = {
            "action": "SEND",
            "recipient": recipient,
            "content": message
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "failed to send message"))

    def delete_message(self, message_id: int) -> None:
        payload = {
            "action": "DELETE_MESSAGE",
            "message_ids": [message_id]
        }
        response = self._send_request(payload)
        if not response.get("success", False):
            raise Exception(response.get("message", "failed to delete message"))

    def close(self) -> None:
        try:
            payload = {"action": "QUIT"}
            self._send_request(payload)
        except Exception:
            pass
        self.sock.close()

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode('utf-8')).hexdigest()


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


class AbstractClient(ABC):
    """Abstract base class defining the client interface"""
    
    @abstractmethod
    def send_request(self, request: dict) -> None:
        """Send a request to the server"""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the connection"""
        pass


class Client(AbstractClient):
    """Real client implementation that talks to the server"""

    def __init__(self, host: str, port: int, incoming_queue: Queue):
        self.host = host
        self.port = port
        self.incoming_queue = incoming_queue
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lock = threading.Lock()
        try:
            self.sock.connect((self.host, self.port))
        except Exception as e:
            raise Exception(f"Cannot connect to server: {e}")
        self.running = True
        self.receiver_thread = threading.Thread(
            target=self._receive_loop, daemon=True
        )
        self.receiver_thread.start()

    def _send_msg(self, data: bytes) -> None:
        """Internal method to send raw bytes with length prefix"""
        try:
            msg = struct.pack("!I", len(data)) + data
            with self.lock:
                self.sock.sendall(msg)
        except Exception as e:
            print(f"Error sending message: {e}")
            self.incoming_queue.put({"type": "connection_error", "error": str(e)})

    def send_request(self, request: dict) -> None:
        """Send a JSON request to the server"""
        try:
            data = json.dumps(request).encode("utf-8")
            self._send_msg(data)
        except Exception as e:
            print(f"Error sending request: {e}")
            self.incoming_queue.put({"type": "connection_error", "error": str(e)})

    def _recvall(self, n: int) -> Optional[bytes]:
        """Internal method to receive exactly n bytes"""
        data = b""
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def _recv_msg(self) -> Optional[bytes]:
        """Internal method to receive a length-prefixed message"""
        raw_len = self._recvall(4)
        if not raw_len:
            return None
        msg_len = struct.unpack("!I", raw_len)[0]
        return self._recvall(msg_len)

    def _receive_loop(self) -> None:
        """Background thread for receiving messages"""
        while self.running:
            try:
                data = self._recv_msg()
                if not data:
                    self.running = False
                    self.incoming_queue.put({"type": "connection_closed"})
                    break
                response = json.loads(data.decode("utf-8"))
                self.incoming_queue.put(response)
            except Exception as e:
                if self.running:
                    print(f"Error receiving message: {e}")
                    self.incoming_queue.put(
                        {"type": "connection_error", "error": str(e)}
                    )
                break

    def close(self) -> None:
        """Close the connection gracefully"""
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        self.sock.close()


class DummyClient(AbstractClient):
    """Mock client for testing/development"""

    def __init__(self, incoming_queue: Queue):
        self.incoming_queue = incoming_queue
        self.users = {"test": "test"}  # Dummy user database
        self.messages = {}  # Dummy message storage

    def send_request(self, request: dict) -> None:
        """
        Handle requests without actual networking.
        Simulates server responses by putting appropriate messages in the queue.
        """
        command = request.get("command")
        data = request.get("data", {})

        if command == "login":
            username = data.get("username")
            self.incoming_queue.put({
                "status": "success",
                "message": f"Login successful. You have 0 unread messages."
            })

        elif command == "create_account":
            username = data.get("username")
            self.users[username] = data.get("password_hash")
            self.incoming_queue.put({
                "status": "success",
                "message": "Account created successfully"
            })

        elif command == "send_message":
            recipient = data.get("recipient")
            message = data.get("message")
            if recipient not in self.messages:
                self.messages[recipient] = []
            self.messages[recipient].append(message)
            self.incoming_queue.put({
                "status": "success",
                "message": "Message sent successfully"
            })

        elif command == "validate_user":
            username = data.get("username")
            self.incoming_queue.put({
                "status": "success",
                "command": "validate_user",
                "username": username,
                "exists": True
            })

    def close(self) -> None:
        """Nothing to close in dummy client"""
        pass
