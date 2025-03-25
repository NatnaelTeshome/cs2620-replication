import grpc
import threading
import queue
import hashlib
import logging
import re
from typing import Optional, Dict, Any, List, Callable, Tuple
from datetime import datetime

import chat_pb2
import chat_pb2_grpc

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class CustomProtocolClient:
    def __init__(self,
                 host: str,
                 port: int,
                 on_msg_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 on_delete_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self.host = host
        self.port = port
        self.channel = None
        self.stub = None
        self.username: Optional[str] = None
        self.connect_to_server(host, port)
        
        self.on_msg_callback = on_msg_callback
        self.on_delete_callback = on_delete_callback
        self._subscription_thread = None
        self._stop_subscription = threading.Event()
        self._max_retries = 3  # Maximum number of retries for leader redirection
        logging.debug("CustomProtocolClient initialized.")

    def connect_to_server(self, host: str, port: int) -> None:
        """Connect to a specific server."""
        # Close existing channel if any
        if self.channel:
            self.channel.close()
            
        self.host = host
        self.port = port
        self.channel = grpc.insecure_channel(f"{host}:{port}")
        self.stub = chat_pb2_grpc.ChatServiceStub(self.channel)
        # Test connectivity
        grpc.channel_ready_future(self.channel).result(timeout=5) 
        logging.debug(f"Connected to server at {host}:{port}")
        
        # Restart subscription if needed
        if self.username and self._subscription_thread:
            self._stop_subscription.set()
            if self._subscription_thread.is_alive():
                self._subscription_thread.join(timeout=1.0)
            self._start_subscription()

    def _extract_leader_info(self, error_message: str) -> Tuple[Optional[str], Optional[int]]:
        """Extract leader host and port from error message."""
        # Look for patterns like "Current leader is node_id" or "Current leader is host:port"
        match = re.search(r"Current leader is (\S+)", error_message)
        if match:
            leader_id = match.group(1).rstrip('.')
            # Check if leader_id contains connection information
            if ':' in leader_id:
                parts = leader_id.split(':')
                if len(parts) == 2:
                    try:
                        return parts[0], int(parts[1])
                    except ValueError:
                        pass
            
            # If we can't directly parse connection info, we need 
            # to have a node_id to connection info mapping
            # For this example, we'll use a simple mapping
            # In a real system, this might come from configuration or discovery
            node_mappings = {
                "1": ("localhost", 50051),
                "2": ("localhost", 50052),
                "3": ("localhost", 50053),
                "4": ("localhost", 50054),
            }
            
            if leader_id in node_mappings:
                return node_mappings[leader_id]
        
        return None, None

    def _execute_with_redirect(self, operation):
        """Execute an operation with automatic leader redirection."""
        retries = 0
        last_error = None
        
        while retries < self._max_retries:
            try:
                return operation()
            except Exception as e:
                error_message = str(e)
                last_error = e
                
                # Check if this is a "not leader" error
                if "Not the leader" in error_message:
                    host, port = self._extract_leader_info(error_message)
                    
                    if host and port:
                        logging.info(f"Redirecting to leader at {host}:{port}")
                        self.connect_to_server(host, port)
                        retries += 1
                        continue
                
                # If we get here, it's either not a leader error or we couldn't parse leader info
                raise e
        
        # If we've exhausted retries
        raise Exception(f"Failed after {retries} leader redirections. Last error: {last_error}")

    def _start_subscription(self):
        if not self.username:
            return
        self._stop_subscription.clear()
        self._subscription_thread = threading.Thread(target=self._listen_to_push_events, daemon=True)
        self._subscription_thread.start()
        logging.debug("Push events subscription started.")

    def _listen_to_push_events(self):
        try:
            request = chat_pb2.SubscribeRequest(username=self.username)
            for event in self.stub.Subscribe(request):
                if self._stop_subscription.is_set():
                    break
                if event.event_type == chat_pb2.NEW_MESSAGE:
                    data = {
                        "id": event.new_message.id,
                        "from_": event.new_message.from_,
                        "to": event.new_message.to,
                        "timestamp": event.new_message.timestamp,
                        "content": event.new_message.content
                    }
                    logging.debug(f"[PUSH] New message received: {data}")
                    if self.on_msg_callback:
                        self.on_msg_callback(data)
                elif event.event_type == chat_pb2.DELETE_MESSAGE:
                    data = {"message_ids": list(event.delete_message.ids)}
                    logging.debug(f"[PUSH] Delete message event received: {data}")
                    if self.on_delete_callback:
                        self.on_delete_callback(data)
                else:
                    logging.warning(f"[PUSH] Unknown event received: {event}")
        except Exception as e:
            if not self._stop_subscription.is_set():
                logging.error(f"Error in push event listener: {e}")
                
                # If this was due to a leader change, try to reconnect
                if "Not the leader" in str(e):
                    host, port = self._extract_leader_info(str(e))
                    if host and port:
                        logging.info(f"Subscription failed, reconnecting to leader at {host}:{port}")
                        self.connect_to_server(host, port)

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    # Modified client methods with leader redirection
    
    def login(self, username: str, password: str) -> str:
        def _operation():
            req = chat_pb2.LoginRequest(username=username, password_hash=self._hash_password(password))
            resp = self.stub.Login(req)
            if not resp.success:
                raise Exception(resp.message)
            self.username = username
            self._start_subscription()
            return resp.message
        
        return self._execute_with_redirect(_operation)

    def send_message(self, recipient: str, message: str) -> int:
        if not self.username:
            raise Exception("Not logged in")
            
        def _operation():
            req = chat_pb2.SendMessageRequest(username=self.username, to=recipient, content=message)
            resp = self.stub.SendMessage(req)
            if not resp.success:
                raise Exception(resp.message)
            logging.info(f"Message sent! Got ID: {resp.id}")
            return resp.id
            
        return self._execute_with_redirect(_operation)

    def account_exists(self, username: str) -> bool:
        def _operation():
            req = chat_pb2.CheckUsernameRequest(username=username)
            resp = self.stub.CheckUsername(req)
            print("Client call", resp.exists, resp.message)
            return resp.exists
            
        return self._execute_with_redirect(_operation)

    def create_account(self, username: str, password: str) -> None:
        def _operation():
            req = chat_pb2.CreateAccountRequest(username=username, password_hash=self._hash_password(password))
            resp = self.stub.CreateAccount(req)
            if not resp.success:
                raise Exception(resp.message)
            self.username = username
            self._start_subscription()
            
        self._execute_with_redirect(_operation)

    def list_accounts(self, pattern: str = "*", offset: int = 0, limit: int = 10) -> List[str]:
        if not self.username:
            raise Exception("Not logged in")
            
        def _operation():
            page_num = (offset // limit) + 1
            req = chat_pb2.ListAccountsRequest(username=self.username, pattern=pattern, page_size=limit, page_num=page_num)
            resp = self.stub.ListAccounts(req)
            if not resp.success:
                raise Exception(resp.message)
            return list(resp.accounts)
            
        return self._execute_with_redirect(_operation)

    def read_messages(self, offset: int = 0, count: int = 10, to_user: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.username:
            raise Exception("Not logged in")
            
        def _operation():
            page_num = (offset // count) + 1
            chat_partner = to_user if to_user else ""
            req = chat_pb2.ReadMessagesRequest(username=self.username, page_size=count, page_num=page_num, chat_partner=chat_partner)
            resp = self.stub.ReadMessages(req)
            if not resp.success:
                raise Exception(resp.message)
            messages = []
            for m in resp.messages:
                messages.append({
                    "id": m.id,
                    "from_": m.from_,
                    "to": m.to,
                    "content": m.content,
                    "read": m.read,
                    "timestamp": m.timestamp
                })
            return messages
            
        return self._execute_with_redirect(_operation)

    def delete_message(self, message_id: int) -> None:
        if not self.username:
            raise Exception("Not logged in")
            
        def _operation():
            req = chat_pb2.DeleteMessageRequest(username=self.username, message_ids=[message_id])
            resp = self.stub.DeleteMessage(req)
            if not resp.success:
                raise Exception(resp.message)
                
        self._execute_with_redirect(_operation)

    def delete_account(self, username: str) -> None:
        if not self.username:
            raise Exception("Not logged in")
            
        def _operation():
            req = chat_pb2.DeleteAccountRequest(username=username)
            resp = self.stub.DeleteAccount(req)
            if not resp.success:
                raise Exception(resp.message)
            # After deletion, clear local username and stop subscription.
            self.username = None
            self._stop_subscription.set()
            
        self._execute_with_redirect(_operation)

    def logout(self) -> None:
        if not self.username:
            return
            
        def _operation():
            req = chat_pb2.LogoutRequest(username=self.username)
            resp = self.stub.Logout(req)
            self.username = None
            self._stop_subscription.set()
            
        self._execute_with_redirect(_operation)

    def close(self) -> None:
        try:
            self.logout()
        except Exception:
            pass
        if self.channel:
            self.channel.close()