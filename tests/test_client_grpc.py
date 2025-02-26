import unittest
from unittest.mock import MagicMock, patch
import hashlib
import threading
import grpc
import os
import sys
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(parent_dir)
import chat_pb2
import chat_pb2_grpc
import chat_pb2
from client_grpc import CustomProtocolClient


class TestCustomProtocolClient(unittest.TestCase):
    def setUp(self):
        # Mock the gRPC channel and stub
        self.mock_channel = MagicMock()
        self.mock_stub = MagicMock()
        
        # Patch the grpc.insecure_channel to return our mock
        self.patcher1 = patch('grpc.insecure_channel', return_value=self.mock_channel)
        self.patcher2 = patch('chat_pb2_grpc.ChatServiceStub', return_value=self.mock_stub)
        self.patcher1.start()
        self.patcher2.start()
        
        # Also patch threading to prevent actual thread creation during tests
        self.patcher3 = patch.object(threading.Thread, 'start')
        self.patcher3.start()
        
        # Create client instance for testing
        self.client = CustomProtocolClient("localhost", 50051)
        
    def tearDown(self):
        # Stop all patchers
        self.patcher1.stop()
        self.patcher2.stop()
        self.patcher3.stop()
        
    def test_initialization(self):
        """Test client initialization with correct parameters"""
        self.assertEqual(self.client.host, "localhost")
        self.assertEqual(self.client.port, 50051)
        self.assertIsNone(self.client.username)
        self.assertIsNotNone(self.client.channel)
        self.assertIsNotNone(self.client.stub)
        
    def test_hash_password(self):
        """Test password hashing works correctly"""
        password = "test_password"
        expected_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        actual_hash = self.client._hash_password(password)
        self.assertEqual(actual_hash, expected_hash)
        
    def test_login_success(self):
        """Test successful login"""
        # Mock the Login response
        mock_resp = MagicMock()
        mock_resp.success = True
        mock_resp.message = "Login successful"
        self.mock_stub.Login.return_value = mock_resp
        
        # Call login
        result = self.client.login("testuser", "testpass")
        
        # Verify stub called correctly
        self.mock_stub.Login.assert_called_once()
        login_req = self.mock_stub.Login.call_args[0][0]
        self.assertEqual(login_req.username, "testuser")
        self.assertEqual(login_req.password_hash, self.client._hash_password("testpass"))
        
        # Verify result
        self.assertEqual(result, "Login successful")
        self.assertEqual(self.client.username, "testuser")
        
    def test_login_failure(self):
        """Test login failure with invalid credentials"""
        # Mock the Login response for failure
        mock_resp = MagicMock()
        mock_resp.success = False
        mock_resp.message = "Invalid credentials"
        self.mock_stub.Login.return_value = mock_resp
        
        # Call login and expect exception
        with self.assertRaises(Exception) as context:
            self.client.login("testuser", "wrongpass")
            
        # Verify exception message
        self.assertEqual(str(context.exception), "Invalid credentials")
        self.assertIsNone(self.client.username)
        
    def test_create_account_success(self):
        """Test successful account creation"""
        # Mock the CreateAccount response
        mock_resp = MagicMock()
        mock_resp.success = True
        mock_resp.message = "Account created"
        self.mock_stub.CreateAccount.return_value = mock_resp
        
        # Call create_account
        self.client.create_account("newuser", "newpass")
        
        # Verify stub called correctly
        self.mock_stub.CreateAccount.assert_called_once()
        create_req = self.mock_stub.CreateAccount.call_args[0][0]
        self.assertEqual(create_req.username, "newuser")
        self.assertEqual(create_req.password_hash, self.client._hash_password("newpass"))
        
        # Verify username set
        self.assertEqual(self.client.username, "newuser")
        
    def test_create_account_failure(self):
        """Test account creation failure"""
        # Mock response for failure
        mock_resp = MagicMock()
        mock_resp.success = False
        mock_resp.message = "Username already exists"
        self.mock_stub.CreateAccount.return_value = mock_resp
        
        # Call create_account and expect exception
        with self.assertRaises(Exception) as context:
            self.client.create_account("existinguser", "pass")
            
        self.assertEqual(str(context.exception), "Username already exists")
        
    def test_account_exists_true(self):
        """Test account exists check with existing account"""
        # Mock the CheckUsername response
        mock_resp = MagicMock()
        mock_resp.exists = True
        self.mock_stub.CheckUsername.return_value = mock_resp
        
        # Call account_exists
        result = self.client.account_exists("existinguser")
        
        # Verify stub called correctly
        self.mock_stub.CheckUsername.assert_called_once()
        check_req = self.mock_stub.CheckUsername.call_args[0][0]
        self.assertEqual(check_req.username, "existinguser")
        
        # Verify result
        self.assertTrue(result)
        
    def test_account_exists_false(self):
        """Test account exists check with non-existent account"""
        # Mock the CheckUsername response
        mock_resp = MagicMock()
        mock_resp.exists = False
        self.mock_stub.CheckUsername.return_value = mock_resp
        
        # Call account_exists
        result = self.client.account_exists("nonexistentuser")
        
        # Verify result
        self.assertFalse(result)
        
    def test_list_accounts_success(self):
        """Test listing accounts with pagination"""
        # Set username to simulate logged in state
        self.client.username = "testuser"
        
        # Mock the ListAccounts response
        mock_resp = MagicMock()
        mock_resp.success = True
        mock_resp.accounts = ["user1", "user2", "user3"]
        self.mock_stub.ListAccounts.return_value = mock_resp
        
        # Call list_accounts with pattern and pagination params
        result = self.client.list_accounts("u*", 10, 5)
        
        # Verify stub called correctly
        self.mock_stub.ListAccounts.assert_called_once()
        list_req = self.mock_stub.ListAccounts.call_args[0][0]
        self.assertEqual(list_req.username, "testuser")
        self.assertEqual(list_req.pattern, "u*")
        self.assertEqual(list_req.page_size, 5)
        self.assertEqual(list_req.page_num, 3)  # (10 // 5) + 1 = 3
        
        # Verify result
        self.assertEqual(result, ["user1", "user2", "user3"])
        
    def test_list_accounts_not_logged_in(self):
        """Test listing accounts when not logged in"""
        # Ensure username is None
        self.client.username = None
        
        # Call list_accounts and expect exception
        with self.assertRaises(Exception) as context:
            self.client.list_accounts()
            
        self.assertEqual(str(context.exception), "Not logged in")
        
    def test_send_message_success(self):
        """Test sending message successfully"""
        # Set username to simulate logged in state
        self.client.username = "testuser"
        
        # Mock the SendMessage response
        mock_resp = MagicMock()
        mock_resp.success = True
        mock_resp.id = 12345
        self.mock_stub.SendMessage.return_value = mock_resp
        
        # Call send_message
        result = self.client.send_message("recipient", "Hello there")
        
        # Verify stub called correctly
        self.mock_stub.SendMessage.assert_called_once()
        send_req = self.mock_stub.SendMessage.call_args[0][0]
        self.assertEqual(send_req.username, "testuser")
        self.assertEqual(send_req.to, "recipient")
        self.assertEqual(send_req.content, "Hello there")
        
        # Verify result
        self.assertEqual(result, 12345)
        
    def test_send_message_not_logged_in(self):
        """Test sending message when not logged in"""
        # Ensure username is None
        self.client.username = None
        
        # Call send_message and expect exception
        with self.assertRaises(Exception) as context:
            self.client.send_message("recipient", "Hello")
            
        self.assertEqual(str(context.exception), "Not logged in")
        
    def test_read_messages_success(self):
        """Test reading messages successfully"""
        # Set username to simulate logged in state
        self.client.username = "testuser"
        
        # Create mock messages
        mock_msg1 = MagicMock()
        mock_msg1.id = 1
        mock_msg1.from_ = "sender1"
        mock_msg1.to = "testuser"
        mock_msg1.content = "Message 1"
        mock_msg1.read = False
        mock_msg1.timestamp = 123456789
        
        mock_msg2 = MagicMock()
        mock_msg2.id = 2
        mock_msg2.from_ = "sender2"
        mock_msg2.to = "testuser"
        mock_msg2.content = "Message 2"
        mock_msg2.read = True
        mock_msg2.timestamp = 123456790
        
        # Mock the ReadMessages response
        mock_resp = MagicMock()
        mock_resp.success = True
        mock_resp.messages = [mock_msg1, mock_msg2]
        self.mock_stub.ReadMessages.return_value = mock_resp
        
        # Call read_messages
        result = self.client.read_messages(5, 10)
        
        # Verify stub called correctly
        self.mock_stub.ReadMessages.assert_called_once()
        read_req = self.mock_stub.ReadMessages.call_args[0][0]
        self.assertEqual(read_req.username, "testuser")
        self.assertEqual(read_req.page_size, 10)
        self.assertEqual(read_req.page_num, 1)  # (5 // 10) + 1 = 1
        
        # Verify result format
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["id"], 1)
        self.assertEqual(result[0]["from_"], "sender1")
        self.assertEqual(result[0]["to"], "testuser")
        self.assertEqual(result[0]["content"], "Message 1")
        self.assertEqual(result[0]["read"], False)
        self.assertEqual(result[0]["timestamp"], 123456789)
        
    def test_read_messages_with_chat_partner(self):
        """Test reading messages with specific chat partner"""
        # Set username to simulate logged in state
        self.client.username = "testuser"
        
        # Mock response with single message
        mock_msg = MagicMock()
        mock_msg.id = 1
        mock_msg.from_ = "partner"
        mock_msg.to = "testuser"
        mock_msg.content = "Message from partner"
        mock_msg.read = False
        mock_msg.timestamp = 123456789
        
        mock_resp = MagicMock()
        mock_resp.success = True
        mock_resp.messages = [mock_msg]
        self.mock_stub.ReadMessages.return_value = mock_resp
        
        # Call read_messages with to_user parameter
        result = self.client.read_messages(0, 10, "partner")
        
        # Verify chat_partner parameter was set
        read_req = self.mock_stub.ReadMessages.call_args[0][0]
        self.assertEqual(read_req.chat_partner, "partner")
        
        # Verify result
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["from_"], "partner")
        
    def test_read_messages_not_logged_in(self):
        """Test reading messages when not logged in"""
        # Ensure username is None
        self.client.username = None
        
        # Call read_messages and expect exception
        with self.assertRaises(Exception) as context:
            self.client.read_messages()
            
        self.assertEqual(str(context.exception), "Not logged in")
        
    def test_delete_message_success(self):
        """Test deleting message successfully"""
        # Set username to simulate logged in state
        self.client.username = "testuser"
        
        # Mock the DeleteMessage response
        mock_resp = MagicMock()
        mock_resp.success = True
        self.mock_stub.DeleteMessage.return_value = mock_resp
        
        # Call delete_message
        self.client.delete_message(12345)
        
        # Verify stub called correctly
        self.mock_stub.DeleteMessage.assert_called_once()
        delete_req = self.mock_stub.DeleteMessage.call_args[0][0]
        self.assertEqual(delete_req.username, "testuser")
        self.assertEqual(delete_req.message_ids, [12345])
        
    def test_delete_message_not_logged_in(self):
        """Test deleting message when not logged in"""
        # Ensure username is None
        self.client.username = None
        
        # Call delete_message and expect exception
        with self.assertRaises(Exception) as context:
            self.client.delete_message(12345)
            
        self.assertEqual(str(context.exception), "Not logged in")
        
    def test_delete_account_success(self):
        """Test deleting account successfully"""
        # Set username to simulate logged in state
        self.client.username = "testuser"
        
        # Mock the DeleteAccount response
        mock_resp = MagicMock()
        mock_resp.success = True
        self.mock_stub.DeleteAccount.return_value = mock_resp
        
        # Call delete_account
        self.client.delete_account("testuser")
        
        # Verify stub called correctly
        self.mock_stub.DeleteAccount.assert_called_once()
        delete_req = self.mock_stub.DeleteAccount.call_args[0][0]
        self.assertEqual(delete_req.username, "testuser")
        
        # Verify username cleared
        self.assertIsNone(self.client.username)
        
    def test_delete_account_not_logged_in(self):
        """Test deleting account when not logged in"""
        # Ensure username is None
        self.client.username = None
        
        # Call delete_account and expect exception
        with self.assertRaises(Exception) as context:
            self.client.delete_account("testuser")
            
        self.assertEqual(str(context.exception), "Not logged in")
        
    def test_logout(self):
        """Test logout functionality"""
        # Set username to simulate logged in state
        self.client.username = "testuser"
        
        # Mock the Logout response
        mock_resp = MagicMock()
        mock_resp.success = True
        self.mock_stub.Logout.return_value = mock_resp
        
        # Call logout
        self.client.logout()
        
        # Verify stub called correctly
        self.mock_stub.Logout.assert_called_once()
        logout_req = self.mock_stub.Logout.call_args[0][0]
        self.assertEqual(logout_req.username, "testuser")
        
        # Verify username cleared
        self.assertIsNone(self.client.username)
        
    def test_logout_not_logged_in(self):
        """Test logout when not logged in"""
        # Ensure username is None
        self.client.username = None
        
        # Call logout
        self.client.logout()
        
        # Verify Logout was not called
        self.mock_stub.Logout.assert_not_called()
        
    def test_close(self):
        """Test close functionality with cleanup"""
        # Set username to simulate logged in state
        self.client.username = "testuser"
        
        # Mock the Logout response
        mock_resp = MagicMock()
        mock_resp.success = True
        self.mock_stub.Logout.return_value = mock_resp
        
        # Call close
        self.client.close()
        
        # Verify logout called and channel closed
        self.mock_stub.Logout.assert_called_once()
        self.mock_channel.close.assert_called_once()
    
    def test_message_callback(self):
        """Test message callback functionality"""
        # Create mock callback function
        mock_callback = MagicMock()
        
        # Create client with message callback
        client = CustomProtocolClient("localhost", 50051, on_msg_callback=mock_callback)
        
        # Simulate message data
        msg_data = {
            "id": 123,
            "from_": "sender",
            "to": "testuser",
            "content": "Hello!",
            "timestamp": 123456789
        }
        
        # Manually call the callback
        client.on_msg_callback(msg_data)
        
        # Verify callback was called with correct data
        mock_callback.assert_called_once_with(msg_data)

    def test_delete_callback(self):
        """Test delete callback functionality"""
        # Create mock callback function
        mock_callback = MagicMock()
        
        # Create client with delete callback
        client = CustomProtocolClient("localhost", 50051, on_delete_callback=mock_callback)
        
        # Simulate delete data
        delete_data = {"message_ids": [123, 456]}
        
        # Manually call the callback
        client.on_delete_callback(delete_data)
        
        # Verify callback was called with correct data
        mock_callback.assert_called_once_with(delete_data)

if __name__ == '__main__':
    unittest.main()
