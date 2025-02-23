import grpc
import threading
import queue
import hashlib
import logging
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime

import chat_pb2
import chat_pb2_grpc

class CustomProtocolClient:
    def __init__(self,
                 host: str,
                 port: int,
                 on_msg_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 on_delete_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self.host = host
        self.port = port
        self.channel = grpc.insecure_channel(f"{host}:{port}")
        self.stub = chat_pb2_grpc.ChatServiceStub(self.channel)
        self.username: Optional[str] = None
        self.on_msg_callback = on_msg_callback
        self.on_delete_callback = on_delete_callback
        self._subscription_thread = None
        self._stop_subscription = threading.Event()
        logging.debug("CustomProtocolClient initialized.")

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
            logging.error(f"Error in push event listener: {e}")

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def login(self, username: str, password: str) -> str:
        req = chat_pb2.LoginRequest(username=username, password_hash=self._hash_password(password))
        resp = self.stub.Login(req)
        if not resp.success:
            raise Exception(resp.message)
        self.username = username
        self._start_subscription()
        return resp.message

    def send_message(self, recipient: str, message: str) -> int:
        if not self.username:
            raise Exception("Not logged in")
        req = chat_pb2.SendMessageRequest(username=self.username, to=recipient, content=message)
        resp = self.stub.SendMessage(req)
        if not resp.success:
            raise Exception(resp.message)
        logging.info(f"Message sent! Got ID: {resp.id}")
        return resp.id

    def account_exists(self, username: str) -> bool:
        req = chat_pb2.CheckUsernameRequest(username=username)
        resp = self.stub.CheckUsername(req)
        # In the original protocol, a response with success True means the username exists.
        return resp.exists

    def create_account(self, username: str, password: str) -> None:
        req = chat_pb2.CreateAccountRequest(username=username, password_hash=self._hash_password(password))
        resp = self.stub.CreateAccount(req)
        if not resp.success:
            raise Exception(resp.message)
        self.username = username
        self._start_subscription()

    def list_accounts(self, pattern: str = "*", offset: int = 0, limit: int = 10) -> List[str]:
        if not self.username:
            raise Exception("Not logged in")
        page_num = (offset // limit) + 1
        req = chat_pb2.ListAccountsRequest(username=self.username, pattern=pattern, page_size=limit, page_num=page_num)
        resp = self.stub.ListAccounts(req)
        if not resp.success:
            raise Exception(resp.message)
        return list(resp.accounts)

    def read_messages(self, offset: int = 0, count: int = 10, to_user: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.username:
            raise Exception("Not logged in")
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

    def delete_message(self, message_id: int) -> None:
        if not self.username:
            raise Exception("Not logged in")
        req = chat_pb2.DeleteMessageRequest(username=self.username, message_ids=[message_id])
        resp = self.stub.DeleteMessage(req)
        if not resp.success:
            raise Exception(resp.message)

    def delete_account(self, username: str) -> None:
        if not self.username:
            raise Exception("Not logged in")
        req = chat_pb2.DeleteAccountRequest(username=username)
        resp = self.stub.DeleteAccount(req)
        if not resp.success:
            raise Exception(resp.message)
        # After deletion, clear local username and stop subscription.
        self.username = None
        self._stop_subscription.set()

    def logout(self) -> None:
        if not self.username:
            return
        req = chat_pb2.LogoutRequest(username=self.username)
        resp = self.stub.Logout(req)
        self.username = None
        self._stop_subscription.set()

    def close(self) -> None:
        try:
            self.logout()
        except Exception:
            pass
        self.channel.close()
