from abc import ABC, abstractmethod
import socket
import threading
import json
import struct
from queue import Queue
from typing import Optional


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
