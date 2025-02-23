import grpc
from concurrent import futures
import time
import json
import shelve
import fnmatch
import threading
import logging
from datetime import datetime

import chat_pb2
import chat_pb2_grpc

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] [%(levelname)s] %(message)s"
)

# --- Persistent Database Setup ---
with open("config.json", "r") as file:
    try:
        config = json.load(file)
    except Exception as e:
        logging.error(f"failed to load config: {e}")
        config = {}

HOST = config.get("HOST", "0.0.0.0")
PORT = config.get("PORT", 50051)

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
    """Persist in-memory data to disk."""
    db["accounts"] = accounts
    db["id_to_message"] = id_to_message
    db["global_message_id"] = global_message_id
    db.sync()

# Lock to ensure thread-safe access to shared data.
data_lock = threading.Lock()

# --- Subscription mechanism for push events ---
# Maps username -> list of queues (one per active subscription)
subscribers = {}
subscribers_lock = threading.Lock()

def add_subscriber(username, queue):
    with subscribers_lock:
        if username not in subscribers:
            subscribers[username] = []
        subscribers[username].append(queue)
        logging.debug(f"Subscriber added for {username}. Total subscribers: {len(subscribers[username])}")

def remove_subscriber(username, queue):
    with subscribers_lock:
        if username in subscribers and queue in subscribers[username]:
            subscribers[username].remove(queue)
            logging.debug(f"Subscriber removed for {username}")

def push_event_to_user(username, event):
    with subscribers_lock:
        if username in subscribers:
            for q in subscribers[username]:
                q.put(event)
            logging.debug(f"Pushed event to {username}: {event}")

# --- gRPC Service Implementation ---
class ChatServiceServicer(chat_pb2_grpc.ChatServiceServicer):

    def Login(self, request, context):
        username = request.username
        password_hash = request.password_hash
        with data_lock:
            if username not in accounts:
                msg = "No such user."
                logging.warning(f"Login failed: {msg} for {username}")
                return chat_pb2.LoginResponse(success=False, message=msg, unread_count=0)
            if accounts[username]["password_hash"] != password_hash:
                msg = "Incorrect password."
                logging.warning(f"Login failed: {msg} for {username}")
                return chat_pb2.LoginResponse(success=False, message=msg, unread_count=0)
            # Count unread messages
            unread = sum(1 for m in accounts[username]["messages"] if not m["read"])
        msg = f"Logged in as '{username}'. Unread messages: {unread}."
        logging.info(f"User '{username}' logged in.")
        return chat_pb2.LoginResponse(success=True, message=msg, unread_count=unread)

    def CreateAccount(self, request, context):
        username = request.username
        password_hash = request.password_hash
        if not username or not password_hash:
            msg = "Username or password not provided."
            logging.warning("CreateAccount failed: missing fields.")
            return chat_pb2.CreateAccountResponse(success=False, message=msg)
        with data_lock:
            if username in accounts:
                msg = "Username already exists."
                logging.warning(f"CreateAccount failed: {msg} for {username}")
                return chat_pb2.CreateAccountResponse(success=False, message=msg)
            accounts[username] = {
                "password_hash": password_hash,
                "messages": [],
                "conversations": {},
            }
            persist_data()
        msg = f"New account '{username}' created."
        logging.info(msg)
        return chat_pb2.CreateAccountResponse(success=True, message=msg)

    def CheckUsername(self, request, context):
        username = request.username
        with data_lock:
            exists = username in accounts
        msg = "Username exists." if exists else "Username does not exist."
        logging.debug(f"CheckUsername: {username} -> {exists}")
        return chat_pb2.CheckUsernameResponse(exists=exists, message=msg)

    def ListAccounts(self, request, context):
        username = request.username
        pattern = request.pattern if request.pattern else "*"
        page_size = request.page_size
        page_num = request.page_num
        with data_lock:
            if username not in accounts:
                msg = "Please log in first."
                logging.warning("ListAccounts failed: user not logged in.")
                return chat_pb2.ListAccountsResponse(success=False, message=msg, accounts=[], total_accounts=0)
            matching = [acct for acct in accounts.keys() if fnmatch.fnmatch(acct, pattern)]
            matching.sort()
            total = len(matching)
            start = (page_num - 1) * page_size
            end = start + page_size
            page_accounts = matching[start:end] if start < total else []
        logging.debug(f"ListAccounts for {username}: page {page_num} with pattern '{pattern}'")
        return chat_pb2.ListAccountsResponse(success=True, message="", accounts=page_accounts, total_accounts=total)

    def SendMessage(self, request, context):
        sender = request.username
        recipient = request.to
        content = request.content.strip()
        if not sender:
            msg = "Not logged in."
            logging.warning("SendMessage failed: sender not provided.")
            return chat_pb2.SendMessageResponse(success=False, message=msg, id=-1)
        if not recipient or not content:
            msg = "Recipient or content missing."
            logging.warning("SendMessage failed: missing recipient or content.")
            return chat_pb2.SendMessageResponse(success=False, message=msg, id=-1)
        with data_lock:
            if recipient not in accounts:
                msg = "Recipient does not exist."
                logging.warning(f"SendMessage failed: {msg} for recipient {recipient}")
                return chat_pb2.SendMessageResponse(success=False, message=msg, id=-1)
            global global_message_id
            global_message_id += 1
            msg_id = global_message_id
            timestamp = int(datetime.now().timestamp())
            new_msg = {
                "id": msg_id,
                "from_": sender,
                "to": recipient,
                "content": content,
                "read": False,
                "timestamp": timestamp,
            }
            # Append to recipient's messages list.
            accounts[recipient]["messages"].append(new_msg)
            # Append to conversations.
            conv = accounts[recipient]["conversations"]
            if sender not in conv:
                conv[sender] = []
            conv[sender].append(new_msg)
            # Save in global mapping.
            id_to_message[msg_id] = new_msg
            persist_data()
        msg_text = f"Message sent to '{recipient}': {content}"
        logging.info(f"User '{sender}' sent message id {msg_id} to '{recipient}'")
        # Push NEW_MESSAGE event if recipient is subscribed.
        push_event = chat_pb2.PushEvent(
            event_type=chat_pb2.NEW_MESSAGE,
            new_message=chat_pb2.NewMessageEvent(
                id=msg_id,
                from_=sender,
                to=recipient,
                timestamp=timestamp,
                content=content
            )
        )
        push_event_to_user(recipient, push_event)
        return chat_pb2.SendMessageResponse(success=True, message=msg_text, id=msg_id)

    def ReadMessages(self, request, context):
        username = request.username
        page_size = request.page_size
        page_num = request.page_num
        chat_partner = request.chat_partner
        messages = []
        total_msgs = 0
        remaining = 0
        total_unread = 0
        remaining_unread = 0
        with data_lock:
            if username not in accounts:
                msg = "Please log in first."
                logging.warning("ReadMessages failed: user not logged in.")
                return chat_pb2.ReadMessagesResponse(success=False, message=msg, messages=[], total_msgs=0, remaining=0, total_unread=0, remaining_unread=0)
            user_data = accounts[username]
            if chat_partner:
                conv = user_data.get("conversations", {}).get(chat_partner, [])
                total_msgs = len(conv)
                start = (page_num - 1) * page_size
                end = min(start + page_size, total_msgs)
                messages = conv[start:end] if start < total_msgs else []
                # Mark messages as read in conversation and in messages list.
                for m in messages:
                    m["read"] = True
                for m in user_data.get("messages", []):
                    if m["id"] in {msg["id"] for msg in messages}:
                        m["read"] = True
                remaining = max(0, total_msgs - end)
                persist_data()
                msg_str = f"Read conversation with {chat_partner}."
                logging.info(f"User '{username}' read conversation with '{chat_partner}'")
                return chat_pb2.ReadMessagesResponse(success=True, message=msg_str,
                    messages=[chat_pb2.ChatMessage(
                        id=m["id"],
                        from_=m["from_"],
                        to=m["to"],
                        content=m["content"],
                        read=m["read"],
                        timestamp=m["timestamp"]
                    ) for m in messages],
                    total_msgs=total_msgs,
                    remaining=remaining,
                    total_unread=0,
                    remaining_unread=0)
            else:
                # Read unread messages.
                unread = [m for m in user_data.get("messages", []) if not m["read"]]
                total_unread = len(unread)
                start = (page_num - 1) * page_size
                end = min(start + page_size, total_unread)
                messages = unread[start:end] if start < total_unread else []
                # Mark them as read.
                for m in messages:
                    m["read"] = True
                # Also mark in conversations.
                for m in messages:
                    sender = m["from_"]
                    if sender in user_data.get("conversations", {}):
                        for conv_msg in user_data["conversations"][sender]:
                            if conv_msg["id"] == m["id"]:
                                conv_msg["read"] = True
                remaining_unread = max(0, total_unread - end)
                persist_data()
                msg_str = "Read unread messages."
                logging.info(f"User '{username}' read {len(messages)} unread messages")
                return chat_pb2.ReadMessagesResponse(success=True, message=msg_str,
                    messages=[chat_pb2.ChatMessage(
                        id=m["id"],
                        from_=m["from_"],
                        to=m["to"],
                        content=m["content"],
                        read=m["read"],
                        timestamp=m["timestamp"]
                    ) for m in messages],
                    total_msgs=0,
                    remaining=0,
                    total_unread=total_unread,
                    remaining_unread=remaining_unread)

    def DeleteMessage(self, request, context):
        username = request.username
        message_ids = list(request.message_ids)
        affected_users = set()
        with data_lock:
            if username not in accounts:
                msg = "Please log in first."
                logging.warning("DeleteMessage failed: user not logged in.")
                return chat_pb2.DeleteMessageResponse(success=False, message=msg)
            # Remove messages from the initiating user’s messages list.
            accounts[username]["messages"] = [m for m in accounts[username].get("messages", []) if m["id"] not in message_ids]
            # Process each message id.
            for mid in message_ids:
                msg_obj = id_to_message.get(mid)
                if not msg_obj:
                    logging.error(f"Message with ID {mid} does not exist.")
                    continue
                sender = msg_obj["from_"]
                receiver = msg_obj["to"]
                affected_users.add(sender)
                affected_users.add(receiver)
                # Remove from receiver's messages
                if receiver in accounts:
                    accounts[receiver]["messages"] = [m for m in accounts[receiver].get("messages", []) if m["id"] != mid]
                    # Remove from receiver's conversations
                    conv = accounts[receiver].get("conversations", {}).get(sender, [])
                    accounts[receiver]["conversations"][sender] = [m for m in conv if m["id"] != mid]
                # Also remove from sender's conversations if present.
                if sender in accounts:
                    conv = accounts[sender].get("conversations", {}).get(receiver, [])
                    accounts[sender]["conversations"][receiver] = [m for m in conv if m["id"] != mid]
                id_to_message.pop(mid, None)
            # Remove the initiating user from affected set.
            affected_users.discard(username)
            persist_data()
        # Notify affected users.
        for user in affected_users:
            push_evt = chat_pb2.PushEvent(
                event_type=chat_pb2.DELETE_MESSAGE,
                delete_message=chat_pb2.DeleteMessageEvent(ids=message_ids)
            )
            push_event_to_user(user, push_evt)
            logging.info(f"Pushed DELETE_MESSAGE event to '{user}'")
        resp_msg = f"Deleted {len(message_ids)} messages."
        logging.info(f"User '{username}' deleted {len(message_ids)} messages")
        return chat_pb2.DeleteMessageResponse(success=True, message=resp_msg)

    def DeleteAccount(self, request, context):
        username = request.username
        with data_lock:
            if username not in accounts:
                msg = "Please log in first."
                logging.warning("DeleteAccount failed: user not logged in.")
                return chat_pb2.DeleteAccountResponse(success=False, message=msg)
            del accounts[username]
            persist_data()
        # Also remove any subscriptions.
        with subscribers_lock:
            subscribers.pop(username, None)
        msg = f"Account '{username}' deleted."
        logging.info(msg)
        return chat_pb2.DeleteAccountResponse(success=True, message=msg)

    def Logout(self, request, context):
        username = request.username
        # In this implementation, logout just removes any subscriptions.
        with subscribers_lock:
            subscribers.pop(username, None)
        msg = f"User '{username}' logged out."
        logging.info(msg)
        return chat_pb2.LogoutResponse(success=True, message=msg)

    def Subscribe(self, request, context):
        username = request.username
        # Optionally, you can check if the user exists.
        import queue
        q = queue.Queue()
        add_subscriber(username, q)
        try:
            while True:
                event = q.get()
                yield event
        except Exception as e:
            logging.error(f"Subscribe exception for {username}: {e}")
        finally:
            remove_subscriber(username, q)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatServiceServicer(), server)
    server.add_insecure_port(f"{HOST}:{PORT}")
    logging.info(f"gRPC server listening on {HOST}:{PORT}")
    server.start()
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
        server.stop(0)
        db.close()

if __name__ == '__main__':
    serve()
