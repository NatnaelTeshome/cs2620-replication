import grpc
from concurrent import futures
import asyncio
import time
import logging
import threading
import fnmatch
from datetime import datetime

# Import our modules
import raft
import storage
from config import ClusterConfig, get_local_ip
import chat_pb2
import chat_pb2_grpc
import raft_pb2
import raft_pb2_grpc

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
)

class ChatServicer(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self, node_id, config, raft_node):
        self.node_id = node_id
        self.config = config
        self.raft_node = raft_node
        
        # Subscription mechanism for push events
        self.subscribers = {}
        self.subscribers_lock = threading.RLock()
        
        # Event loop for async operations
        self.loop = asyncio.new_event_loop()
        
        logging.info(f"Chat service initialized for node {node_id}")
    
    def Login(self, request, context):
        username = request.username
        password_hash = request.password_hash
        
        # Create a login command
        command = {
            "type": "login",
            "username": username,
            "password_hash": password_hash
        }
        
        # Submit the command to Raft and wait for the result
        success, result = self.loop.run_until_complete(self.raft_node.submit_command(command))
        
        if not success:
            # If the command was not successful, check if it was because we're not the leader
            if "Not the leader" in result:
                # Return a response indicating the client should retry with the leader
                return chat_pb2.LoginResponse(
                    success=False,
                    message=result,
                    unread_count=0
                )
            
            # Otherwise, return the error
            return chat_pb2.LoginResponse(
                success=False,
                message=result,
                unread_count=0
            )
        
        # Parse the result
        login_success, message, unread_count = result
        
        return chat_pb2.LoginResponse(
            success=login_success,
            message=message,
            unread_count=unread_count
        )
    
    def CreateAccount(self, request, context):
        username = request.username
        password_hash = request.password_hash
        
        if not username or not password_hash:
            return chat_pb2.CreateAccountResponse(
                success=False,
                message="Username or password not provided."
            )
        
        # Create a create_account command
        command = {
            "type": "create_account",
            "username": username,
            "password_hash": password_hash
        }
        
        # Submit the command to Raft and wait for the result
        success, result = self.loop.run_until_complete(self.raft_node.submit_command(command))
        
        if not success:
            return chat_pb2.CreateAccountResponse(
                success=False,
                message=result
            )
        
        # Parse the result
        create_success, message = result
        
        return chat_pb2.CreateAccountResponse(
            success=create_success,
            message=message
        )
    
    def CheckUsername(self, request, context):
        username = request.username
        
        # Create a check_username command
        command = {
            "type": "check_username",
            "username": username
        }
        
        # Submit the command to Raft and wait for the result
        success, result = self.loop.run_until_complete(self.raft_node.submit_command(command))
        print("Result of chat_server", success, result)
        if not success:
            return chat_pb2.CheckUsernameResponse(
                exists=False,
                message=result
            )
        
        # Parse the result
        exists, message = result
        
        return chat_pb2.CheckUsernameResponse(
            exists=exists,
            message=message
        )
    
    def ListAccounts(self, request, context):
        username = request.username
        pattern = request.pattern if request.pattern else "*"
        page_size = request.page_size
        page_num = request.page_num
        
        # Create a list_accounts command
        command = {
            "type": "list_accounts",
            "username": username,
            "pattern": pattern,
            "page_size": page_size,
            "page_num": page_num
        }
        
        # Submit the command to Raft and wait for the result
        success, result = self.loop.run_until_complete(self.raft_node.submit_command(command))
        
        if not success:
            return chat_pb2.ListAccountsResponse(
                success=False,
                message=result,
                accounts=[],
                total_accounts=0
            )
        
        # Parse the result
        list_success, message, accounts, total_accounts = result
        
        return chat_pb2.ListAccountsResponse(
            success=list_success,
            message=message,
            accounts=accounts,
            total_accounts=total_accounts
        )
    
    def SendMessage(self, request, context):
        sender = request.username
        recipient = request.to
        content = request.content.strip()
        
        if not sender:
            return chat_pb2.SendMessageResponse(
                success=False,
                message="Not logged in.",
                id=-1
            )
        
        if not recipient or not content:
            return chat_pb2.SendMessageResponse(
                success=False,
                message="Recipient or content missing.",
                id=-1
            )
        
        # Create a send_message command
        command = {
            "type": "send_message",
            "from_": sender,
            "to": recipient,
            "content": content
        }
        
        # Submit the command to Raft and wait for the result
        success, result = self.loop.run_until_complete(self.raft_node.submit_command(command))
        
        if not success:
            return chat_pb2.SendMessageResponse(
                success=False,
                message=result,
                id=-1
            )
        
        # Parse the result
        send_success, message, msg_id = result
        
        # If successful, push a NEW_MESSAGE event to the recipient
        if send_success:
            timestamp = int(datetime.now().timestamp())
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
            self._push_event_to_user(recipient, push_event)
        
        return chat_pb2.SendMessageResponse(
            success=send_success,
            message=message,
            id=msg_id
        )
    
    def ReadMessages(self, request, context):
        username = request.username
        page_size = request.page_size
        page_num = request.page_num
        chat_partner = request.chat_partner
        
        # Create a read_messages command
        command = {
            "type": "read_messages",
            "username": username,
            "page_size": page_size,
            "page_num": page_num,
            "chat_partner": chat_partner
        }
        
        # Submit the command to Raft and wait for the result
        success, result = self.loop.run_until_complete(self.raft_node.submit_command(command))
        
        if not success:
            return chat_pb2.ReadMessagesResponse(
                success=False,
                message=result,
                messages=[],
                total_msgs=0,
                remaining=0,
                total_unread=0,
                remaining_unread=0
            )
        
        # Parse the result
        read_success, message, messages, total_msgs, remaining, total_unread, remaining_unread = result
        
        # Convert dictionary messages to ChatMessage protocol buffer objects
        pb_messages = []
        for msg in messages:
            pb_messages.append(chat_pb2.ChatMessage(
                id=msg["id"],
                from_=msg["from_"],
                to=msg["to"],
                content=msg["content"],
                read=msg["read"],
                timestamp=msg["timestamp"]
            ))
        
        return chat_pb2.ReadMessagesResponse(
            success=read_success,
            message=message,
            messages=pb_messages,
            total_msgs=total_msgs,
            remaining=remaining,
            total_unread=total_unread,
            remaining_unread=remaining_unread
        )
    
    def DeleteMessage(self, request, context):
        username = request.username
        message_ids = list(request.message_ids)
        
        # Create a delete_message command
        command = {
            "type": "delete_message",
            "username": username,
            "message_ids": message_ids
        }
        
        # Submit the command to Raft and wait for the result
        success, result = self.loop.run_until_complete(self.raft_node.submit_command(command))
        
        if not success:
            return chat_pb2.DeleteMessageResponse(
                success=False,
                message=result
            )
        
        # Parse the result
        delete_success, message, affected_users = result
        
        # If successful, push a DELETE_MESSAGE event to affected users
        if delete_success:
            for user in affected_users:
                push_event = chat_pb2.PushEvent(
                    event_type=chat_pb2.DELETE_MESSAGE,
                    delete_message=chat_pb2.DeleteMessageEvent(
                        ids=message_ids
                    )
                )
                self._push_event_to_user(user, push_event)
        
        return chat_pb2.DeleteMessageResponse(
            success=delete_success,
            message=message
        )
    
    def DeleteAccount(self, request, context):
        username = request.username
        
        # Create a delete_account command
        command = {
            "type": "delete_account",
            "username": username
        }
        
        # Submit the command to Raft and wait for the result
        success, result = self.loop.run_until_complete(self.raft_node.submit_command(command))
        
        if not success:
            return chat_pb2.DeleteAccountResponse(
                success=False,
                message=result
            )
        
        # Parse the result
        delete_success, message = result
        
        # If successful, remove any subscriptions
        if delete_success:
            with self.subscribers_lock:
                self.subscribers.pop(username, None)
        
        return chat_pb2.DeleteAccountResponse(
            success=delete_success,
            message=message
        )
    
    def Logout(self, request, context):
        username = request.username
        
        # In this implementation, logout just removes any subscriptions
        with self.subscribers_lock:
            self.subscribers.pop(username, None)
        
        msg = f"User '{username}' logged out."
        logging.info(msg)
        
        return chat_pb2.LogoutResponse(
            success=True,
            message=msg
        )
    
    def Subscribe(self, request, context):
        username = request.username
        
        # Create a queue for this subscription
        import queue
        q = queue.Queue()
        
        # Add the subscription
        self._add_subscriber(username, q)
        
        try:
            while True:
                # Wait for events
                event = q.get()
                yield event
        except Exception as e:
            logging.error(f"Subscribe exception for {username}: {e}")
        finally:
            # Remove the subscription when done
            self._remove_subscriber(username, q)
    
    def _add_subscriber(self, username, queue):
        with self.subscribers_lock:
            if username not in self.subscribers:
                self.subscribers[username] = []
            self.subscribers[username].append(queue)
            logging.debug(f"Subscriber added for {username}. Total subscribers: {len(self.subscribers[username])}")
    
    def _remove_subscriber(self, username, queue):
        with self.subscribers_lock:
            if username in self.subscribers and queue in self.subscribers[username]:
                self.subscribers[username].remove(queue)
                logging.debug(f"Subscriber removed for {username}")
    
    def _push_event_to_user(self, username, event):
        with self.subscribers_lock:
            if username in self.subscribers:
                for q in self.subscribers[username]:
                    q.put(event)
                logging.debug(f"Pushed event to {username}: {event}")


class ChatServer:
    def __init__(self, node_id, config_file=None, host=None, port=None, raft_port=None, make_leader=False):
        # Load or create cluster configuration
        self.config = ClusterConfig(config_file, node_id)
        
        # If this is a new node, add it to the config
        if node_id not in self.config.get_nodes():
            host = host or get_local_ip()
            port = port or 50051
            raft_port = raft_port or 50052
            self.config.add_node(node_id, host, port, raft_port)
        
        # Get node information
        self.node_id = node_id
        node_info = self.config.get_node(node_id)
        if not node_info:
            raise ValueError(f"Node {node_id} not found in config")
        
        self.host = node_info["host"]
        self.port = node_info["port"]
        self.raft_port = node_info["raft_port"]
        
        # Initialize state machine
        self.state_machine = storage.StateMachine(node_id)
        
        # Initialize Raft node
        self.raft_node = raft.RaftNode(node_id, self.config, self.state_machine, make_leader)
        
        # Initialize Chat service
        self.servicer = ChatServicer(node_id, self.config, self.raft_node)
        
        # Initialize gRPC server
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        chat_pb2_grpc.add_ChatServiceServicer_to_server(self.servicer, self.server)
        
        # Start the server
        self.server.add_insecure_port(f"{self.host}:{self.port}")
        self.server.start()
        
        logging.info(f"Chat server started on {self.host}:{self.port}")
    
    def join_cluster(self, leader_host, leader_port):
        """Join an existing cluster by contacting the leader."""
        # Connect to the leader
        channel = grpc.insecure_channel(f"{leader_host}:{leader_port}")
        stub = raft_pb2_grpc.RaftServiceStub(channel)
        
        # Send a request to add this node to the cluster
        request = raft_pb2.AddNodeRequest(
            node_id=self.node_id,
            host=self.host,
            port=self.port,
            raft_port=self.raft_port
        )
        
        try:
            response = stub.AddNode(request)
            if response.success:
                logging.info(f"Successfully joined cluster: {response.message}")
                return True
            else:
                logging.error(f"Failed to join cluster: {response.message}")
                return False
        except Exception as e:
            logging.error(f"Error joining cluster: {e}")
            return False
    
    def stop(self):
        """Stop the server."""
        self.server.stop(0)
        self.raft_node.stop()
        self.state_machine.close()
        logging.info("Server stopped")


def start_server(node_id, config_file=None, host=None, port=None, raft_port=None, leader_host=None, leader_port=None):
    """Start a chat server."""
    print("port", port, flush=True)
    server = None 
    # If leader information is provided, join the cluster
    if leader_host and leader_port:
        server = ChatServer(node_id, config_file, host, port, raft_port)
        server.join_cluster(leader_host, leader_port)
    else:
        server = ChatServer(node_id, config_file, host, port, raft_port, True)
    return server


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Start a chat server")
    parser.add_argument("--node-id", required=True, help="Unique ID for this node")
    parser.add_argument("--config", help="Path to cluster configuration file")
    parser.add_argument("--host", help="Host address")
    parser.add_argument("--port", type=int, help="Port for chat service")
    parser.add_argument("--raft-port", type=int, help="Port for Raft consensus")
    parser.add_argument("--leader-host", help="Leader host (if joining an existing cluster)")
    parser.add_argument("--leader-port", type=int, help="Leader Raft port (if joining an existing cluster)")
    
    args = parser.parse_args()
    
    server = start_server(
        args.node_id,
        args.config,
        args.host,
        args.port,
        args.raft_port,
        args.leader_host,
        args.leader_port
    )
    
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
        server.stop()