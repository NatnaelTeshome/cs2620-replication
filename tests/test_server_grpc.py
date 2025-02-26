import unittest
from unittest.mock import MagicMock, patch, Mock, call
import threading
import queue
import time
import json
import hashlib
import builtins
import os
import sys

# Mock the config.json file before importing the server module
# This prevents the FileNotFoundError when the module is loaded
mock_config = {"HOST": "0.0.0.0", "PORT": 50051}
original_open = open

def mock_open_wrapper(filename, *args, **kwargs):
    if filename == "config.json":
        mock_file = MagicMock()
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=None)
        mock_file.read = MagicMock(return_value=json.dumps(mock_config))
        return mock_file
    return original_open(filename, *args, **kwargs)

# Apply the patch before importing the server module
with patch('builtins.open', mock_open_wrapper):
    # Add the parent directory to sys.path if needed to find the modules
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    
    # Now we can safely import the server module and protobuf modules
    import chat_pb2
    import chat_pb2_grpc
    

    from server_grpc import ChatServiceServicer, push_event_to_user, add_subscriber, remove_subscriber
    # If it's server_grpc.py, use this instead:
    # from server_grpc import ChatServiceServicer, push_event_to_user, add_subscriber, remove_subscriber


class TestChatServiceServicer(unittest.TestCase):
    def setUp(self):
        # Create isolated test environment
        self.patcher1 = patch('server_grpc.accounts', {})
        self.patcher2 = patch('server_grpc.id_to_message', {})
        self.patcher3 = patch('server_grpc.global_message_id', 0)
        self.patcher4 = patch('server_grpc.subscribers', {})
        
        # Start the patchers
        self.mock_accounts = self.patcher1.start()
        self.mock_id_to_message = self.patcher2.start()
        self.mock_global_message_id = self.patcher3.start()
        self.mock_subscribers = self.patcher4.start()
        
        # Mock persistance function to avoid actual disk writes
        self.patcher_persist = patch('server_grpc.persist_data')
        self.mock_persist = self.patcher_persist.start()
        
        # Create a servicer instance for testing
        self.servicer = ChatServiceServicer()
        
        # Mock gRPC context
        self.context = MagicMock()
        
        # Add a test user to accounts for testing
        self.test_password = "testpass"
        self.password_hash = hashlib.sha256(self.test_password.encode("utf-8")).hexdigest()
        self.mock_accounts["testuser"] = {
            "password_hash": self.password_hash,
            "messages": [],
            "conversations": {}
        }
        
    def tearDown(self):
        # Stop all patchers
        self.patcher1.stop()
        self.patcher2.stop()
        self.patcher3.stop()
        self.patcher4.stop()
        self.patcher_persist.stop()
    
    # ========== Authentication Tests ==========
    
    def test_login_success(self):
        """Test successful login attempt"""
        # Create login request with valid credentials
        request = chat_pb2.LoginRequest(
            username="testuser",
            password_hash=self.password_hash
        )
        
        # Call Login
        response = self.servicer.Login(request, self.context)
        
        # Verify response
        self.assertTrue(response.success)
        self.assertIn("Logged in", response.message)
        self.assertEqual(response.unread_count, 0)
    
    def test_login_failure_no_user(self):
        """Test login with non-existent user"""
        request = chat_pb2.LoginRequest(
            username="nonexistentuser",
            password_hash=self.password_hash
        )
        
        response = self.servicer.Login(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("No such user", response.message)
    
    def test_login_failure_wrong_password(self):
        """Test login with incorrect password"""
        wrong_password_hash = hashlib.sha256("wrongpass".encode("utf-8")).hexdigest()
        request = chat_pb2.LoginRequest(
            username="testuser",
            password_hash=wrong_password_hash
        )
        
        response = self.servicer.Login(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("Incorrect password", response.message)
    
    def test_create_account_success(self):
        """Test successful account creation"""
        request = chat_pb2.CreateAccountRequest(
            username="newuser",
            password_hash="newhash"
        )
        
        response = self.servicer.CreateAccount(request, self.context)
        
        self.assertTrue(response.success)
        self.assertIn("created", response.message)
        self.assertIn("newuser", self.mock_accounts)
        self.assertEqual(self.mock_accounts["newuser"]["password_hash"], "newhash")
        self.mock_persist.assert_called_once()
    
    def test_create_account_failure_missing_fields(self):
        """Test account creation with missing fields"""
        request = chat_pb2.CreateAccountRequest(
            username="",
            password_hash=""
        )
        
        response = self.servicer.CreateAccount(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("not provided", response.message)
    
    def test_create_account_failure_existing_username(self):
        """Test account creation with existing username"""
        request = chat_pb2.CreateAccountRequest(
            username="testuser",
            password_hash="somehash"
        )
        
        response = self.servicer.CreateAccount(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("already exists", response.message)
    
    def test_check_username_exists(self):
        """Test checking existing username"""
        request = chat_pb2.CheckUsernameRequest(username="testuser")
        
        response = self.servicer.CheckUsername(request, self.context)
        
        self.assertTrue(response.exists)
        self.assertIn("exists", response.message)
    
    def test_check_username_not_exists(self):
        """Test checking non-existent username"""
        request = chat_pb2.CheckUsernameRequest(username="nonexistentuser")
        
        response = self.servicer.CheckUsername(request, self.context)
        
        self.assertFalse(response.exists)
        self.assertIn("does not exist", response.message)
    
    def test_delete_account_success(self):
        """Test successful account deletion"""
        request = chat_pb2.DeleteAccountRequest(username="testuser")
        
        response = self.servicer.DeleteAccount(request, self.context)
        
        self.assertTrue(response.success)
        self.assertIn("deleted", response.message)
        self.assertNotIn("testuser", self.mock_accounts)
        self.mock_persist.assert_called_once()
    
    def test_delete_account_failure_not_logged_in(self):
        """Test account deletion when account doesn't exist"""
        request = chat_pb2.DeleteAccountRequest(username="nonexistentuser")
        
        response = self.servicer.DeleteAccount(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("log in", response.message)
    
    def test_logout(self):
        """Test successful logout"""
        # Setup: add a subscriber
        with patch('server_grpc.subscribers', {"testuser": ["queue1"]}):
            request = chat_pb2.LogoutRequest(username="testuser")
            
            response = self.servicer.Logout(request, self.context)
            
            self.assertTrue(response.success)
            self.assertIn("logged out", response.message)
            self.assertNotIn("testuser", self.mock_subscribers)
    
    # ========== Message Operation Tests ==========
    
    def test_send_message_success(self):
        """Test successful message sending"""
        # Add a recipient
        self.mock_accounts["recipient"] = {
            "password_hash": "somehash",
            "messages": [],
            "conversations": {}
        }
        
        request = chat_pb2.SendMessageRequest(
            username="testuser",
            to="recipient",
            content="Hello, recipient!"
        )
        
        # Mock push_event_to_user
        with patch('server_grpc.push_event_to_user') as mock_push:
            response = self.servicer.SendMessage(request, self.context)
            
            self.assertTrue(response.success)
            self.assertIn("Message sent", response.message)
            self.assertGreater(response.id, 0)
            
            # Verify message stored properly
            self.assertEqual(len(self.mock_accounts["recipient"]["messages"]), 1)
            self.assertEqual(self.mock_accounts["recipient"]["messages"][0]["content"], "Hello, recipient!")
            self.assertEqual(self.mock_accounts["recipient"]["messages"][0]["from_"], "testuser")
            
            # Verify conversation updated
            self.assertIn("testuser", self.mock_accounts["recipient"]["conversations"])
            self.assertEqual(len(self.mock_accounts["recipient"]["conversations"]["testuser"]), 1)
            
            # Verify global map updated
            self.assertIn(response.id, self.mock_id_to_message)
            
            # Verify push notification
            mock_push.assert_called_once()
    
    def test_send_message_failure_not_logged_in(self):
        """Test sending message when not logged in"""
        request = chat_pb2.SendMessageRequest(
            username="",
            to="recipient",
            content="Hello"
        )
        
        response = self.servicer.SendMessage(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("Not logged in", response.message)
    
    def test_send_message_failure_missing_fields(self):
        """Test sending message with missing fields"""
        request = chat_pb2.SendMessageRequest(
            username="testuser",
            to="",
            content=""
        )
        
        response = self.servicer.SendMessage(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("missing", response.message)
    
    def test_send_message_failure_recipient_not_exist(self):
        """Test sending message to non-existent recipient"""
        request = chat_pb2.SendMessageRequest(
            username="testuser",
            to="nonexistentuser",
            content="Hello"
        )
        
        response = self.servicer.SendMessage(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("not exist", response.message)
    
    def test_read_messages_unread(self):
        """Test reading unread messages"""
        # Add unread messages
        self.mock_accounts["testuser"]["messages"] = [
            {
                "id": 1,
                "from_": "sender1",
                "to": "testuser",
                "content": "Message 1",
                "read": False,
                "timestamp": 123456789
            },
            {
                "id": 2,
                "from_": "sender2",
                "to": "testuser",
                "content": "Message 2",
                "read": False,
                "timestamp": 123456790
            }
        ]
        self.mock_accounts["testuser"]["conversations"] = {
            "sender1": [self.mock_accounts["testuser"]["messages"][0]],
            "sender2": [self.mock_accounts["testuser"]["messages"][1]]
        }
        
        request = chat_pb2.ReadMessagesRequest(
            username="testuser",
            page_size=10,
            page_num=1
        )
        
        response = self.servicer.ReadMessages(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(len(response.messages), 2)
        self.assertEqual(response.total_unread, 2)
        
        # Verify messages marked as read
        self.assertTrue(self.mock_accounts["testuser"]["messages"][0]["read"])
        self.assertTrue(self.mock_accounts["testuser"]["messages"][1]["read"])
        self.assertTrue(self.mock_accounts["testuser"]["conversations"]["sender1"][0]["read"])
        self.assertTrue(self.mock_accounts["testuser"]["conversations"]["sender2"][0]["read"])
    
    def test_read_messages_conversation(self):
        """Test reading conversation with specific partner"""
        # Add messages from specific partner
        self.mock_accounts["testuser"]["conversations"]["partner"] = [
            {
                "id": 1,
                "from_": "partner",
                "to": "testuser",
                "content": "Message 1",
                "read": False,
                "timestamp": 123456789
            },
            {
                "id": 2,
                "from_": "partner",
                "to": "testuser",
                "content": "Message 2",
                "read": False,
                "timestamp": 123456790
            }
        ]
        self.mock_accounts["testuser"]["messages"] = self.mock_accounts["testuser"]["conversations"]["partner"].copy()
        
        request = chat_pb2.ReadMessagesRequest(
            username="testuser",
            page_size=10,
            page_num=1,
            chat_partner="partner"
        )
        
        response = self.servicer.ReadMessages(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(len(response.messages), 2)
        self.assertEqual(response.total_msgs, 2)
        
        # Verify messages marked as read
        self.assertTrue(self.mock_accounts["testuser"]["conversations"]["partner"][0]["read"])
        self.assertTrue(self.mock_accounts["testuser"]["conversations"]["partner"][1]["read"])
    
    def test_read_messages_pagination(self):
        """Test pagination for reading messages"""
        # Add many messages
        self.mock_accounts["testuser"]["messages"] = [
            {
                "id": i,
                "from_": f"sender{i}",
                "to": "testuser",
                "content": f"Message {i}",
                "read": False,
                "timestamp": 123456789 + i
            } for i in range(1, 11)  # 10 messages
        ]
        
        request = chat_pb2.ReadMessagesRequest(
            username="testuser",
            page_size=5,  # Get 5 per page
            page_num=1    # First page
        )
        
        response = self.servicer.ReadMessages(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(len(response.messages), 5)  # Only 5 messages returned
        self.assertEqual(response.total_unread, 10)
        self.assertEqual(response.remaining_unread, 5)  # 5 remain for next page
    
    def test_read_messages_failure_not_logged_in(self):
        """Test reading messages when not logged in"""
        request = chat_pb2.ReadMessagesRequest(
            username="nonexistentuser",
            page_size=10,
            page_num=1
        )
        
        response = self.servicer.ReadMessages(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("log in", response.message)
    
    def test_delete_message_success(self):
        """Test successful message deletion"""
        # Add message to be deleted
        msg_id = 12345
        test_msg = {
            "id": msg_id,
            "from_": "sender",
            "to": "testuser",
            "content": "Delete me",
            "read": False,
            "timestamp": 123456789
        }
        
        # Add message to both users
        self.mock_accounts["testuser"]["messages"] = [test_msg]
        self.mock_accounts["testuser"]["conversations"] = {"sender": [test_msg]}
        
        # Add sender account
        self.mock_accounts["sender"] = {
            "password_hash": "senderhash",
            "messages": [],
            "conversations": {"testuser": [test_msg]}
        }
        
        # Add to global message map
        self.mock_id_to_message[msg_id] = test_msg
        
        request = chat_pb2.DeleteMessageRequest(
            username="testuser",
            message_ids=[msg_id]
        )
        
        # Mock push_event_to_user
        with patch('server_grpc.push_event_to_user') as mock_push:
            response = self.servicer.DeleteMessage(request, self.context)
            
            self.assertTrue(response.success)
            self.assertIn("Deleted", response.message)
            
            # Verify message removed from all locations
            self.assertEqual(len(self.mock_accounts["testuser"]["messages"]), 0)
            self.assertEqual(len(self.mock_accounts["testuser"]["conversations"]["sender"]), 0)
            self.assertEqual(len(self.mock_accounts["sender"]["conversations"]["testuser"]), 0)
            self.assertNotIn(msg_id, self.mock_id_to_message)
            
            # Verify notification sent to affected user
            mock_push.assert_called_once()
    
    def test_delete_message_failure_not_logged_in(self):
        """Test message deletion when not logged in"""
        request = chat_pb2.DeleteMessageRequest(
            username="nonexistentuser",
            message_ids=[12345]
        )
        
        response = self.servicer.DeleteMessage(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("log in", response.message)
    
    # ========== Account Listing Tests ==========
    
    def test_list_accounts_success(self):
        """Test successful account listing"""
        # Add more test accounts
        self.mock_accounts["user1"] = {"password_hash": "hash1", "messages": [], "conversations": {}}
        self.mock_accounts["user2"] = {"password_hash": "hash2", "messages": [], "conversations": {}}
        self.mock_accounts["admin1"] = {"password_hash": "hash3", "messages": [], "conversations": {}}
        
        request = chat_pb2.ListAccountsRequest(
            username="testuser",
            pattern="user*",  # Only match user1, user2
            page_size=10,
            page_num=1
        )
        
        response = self.servicer.ListAccounts(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(len(response.accounts), 2)
        self.assertIn("user1", response.accounts)
        self.assertIn("user2", response.accounts)
        self.assertNotIn("admin1", response.accounts)
        self.assertEqual(response.total_accounts, 2)
    
    def test_list_accounts_pagination(self):
        """Test account listing with pagination"""
        # Add test accounts
        for i in range(1, 11):  # 10 accounts
            self.mock_accounts[f"user{i}"] = {"password_hash": f"hash{i}", "messages": [], "conversations": {}}
        
        request = chat_pb2.ListAccountsRequest(
            username="testuser",
            pattern="user*",
            page_size=5,  # 5 per page
            page_num=1    # First page
        )
        
        response = self.servicer.ListAccounts(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(len(response.accounts), 5)  # Only 5 accounts returned
        self.assertEqual(response.total_accounts, 10)
    
    def test_list_accounts_failure_not_logged_in(self):
        """Test account listing when not logged in"""
        request = chat_pb2.ListAccountsRequest(
            username="nonexistentuser",
            pattern="*",
            page_size=10,
            page_num=1
        )
        
        response = self.servicer.ListAccounts(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn("log in", response.message)
    
    # ========== Push Notification Tests ==========
    
    def test_add_subscriber(self):
        """Test adding a subscriber"""
        username = "testuser"
        mock_queue = queue.Queue()
        
        with patch('server_grpc.subscribers', {}) as mock_subscribers:
            add_subscriber(username, mock_queue)
            
            self.assertIn(username, mock_subscribers)
            self.assertEqual(len(mock_subscribers[username]), 1)
            self.assertEqual(mock_subscribers[username][0], mock_queue)
    
    def test_remove_subscriber(self):
        """Test removing a subscriber"""
        username = "testuser"
        mock_queue = queue.Queue()
        
        with patch('server_grpc.subscribers', {username: [mock_queue]}) as mock_subscribers:
            remove_subscriber(username, mock_queue)
            
            self.assertEqual(len(mock_subscribers[username]), 0)
    
    def test_push_event_to_user(self):
        """Test pushing events to subscribers"""
        username = "testuser"
        mock_queue1 = queue.Queue()
        mock_queue2 = queue.Queue()
        mock_event = "test_event"
        
        with patch('server_grpc.subscribers', {username: [mock_queue1, mock_queue2]}):
            push_event_to_user(username, mock_event)
            
            # Verify event was pushed to both queues
            self.assertEqual(mock_queue1.get(), mock_event)
            self.assertEqual(mock_queue2.get(), mock_event)
    
    def test_subscribe_yield_events(self):
        """Test Subscribe method yields events to client"""
        # This is a more complex test that requires handling the generator
        request = chat_pb2.SubscribeRequest(username="testuser")
        
        # Create a mock queue that we'll use to verify events
        test_queue = queue.Queue()
        test_event = chat_pb2.PushEvent(event_type=chat_pb2.NEW_MESSAGE)
        
        # Add the queue to subscribers when add_subscriber is called
        def mock_add_subscriber(username, q):
            # Put the test event in the queue to be yielded
            q.put(test_event)
        
        with patch('server_grpc.add_subscriber', side_effect=mock_add_subscriber), \
             patch('server_grpc.remove_subscriber'):
            
            # Get the generator from Subscribe
            generator = self.servicer.Subscribe(request, self.context)
            
            # Get the first (and only) yielded event
            yielded_event = next(generator)
            
            # Verify it matches our test event
            self.assertEqual(yielded_event, test_event)
            
            # Force the generator to exit by raising an exception
            with self.assertRaises(StopIteration):
                generator.throw(Exception("Test exception"))

if __name__ == '__main__':
    unittest.main()