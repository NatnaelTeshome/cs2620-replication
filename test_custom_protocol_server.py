import unittest
import struct
import json

# For our tests we assume the following names are imported from your chat server module.
# (If they are in the same file, you may remove the import statement and run the tests.)
from server_custom_wp_no_persistence import (
    encode_list_accounts_data,
    encode_conversation_data,
    encode_unread_data,
    encode_response_bin,
    encode_event,
    encode_new_message_event,
    encode_delete_message_event,
    decode_message_from_buffer,
    VERSION,
    OP_CODES_DICT,
)

class TestProtocolEncodings(unittest.TestCase):

    def test_encode_list_accounts_data(self):
        # Prepare input data.
        data = {"total_accounts": 2, "accounts": ["alice", "bob"]}
        # Expected:
        # 4-byte unsigned int (total_accounts = 2)
        # 2-byte unsigned short (# accounts = 2)
        # For each account: 2-byte length + account bytes.
        expected = (
            struct.pack("!I", 2) +
            struct.pack("!H", 2) +
            struct.pack("!H", len("alice".encode("utf-8"))) + b"alice" +
            struct.pack("!H", len("bob".encode("utf-8"))) + b"bob"
        )
        result = encode_list_accounts_data(data)
        self.assertEqual(result, expected)

    def test_encode_conversation_data(self):
        # Prepare sample conversation data.
        msg = {"id": 123, "content": "hello", "read": False, "timestamp": 1610000000}
        data = {
            "conversation_with": "bob",
            "page_num": 2,
            "page_size": 10,
            "total_msgs": 5,
            "remaining": 3,
            "messages": [msg]
        }
        conv_bytes = "bob".encode("utf-8")
        expected = (
            struct.pack("!B", 1) +                                   # flag for conversation response
            struct.pack("!H", len(conv_bytes)) + conv_bytes +        # conversation_with string length + bytes
            struct.pack("!HH", 2, 10) +                               # page_num and page_size (each 2 bytes)
            struct.pack("!II", 5, 3) +                                # total_msgs and remaining (each 4 bytes)
            struct.pack("!H", 1) +                                    # number of messages
            struct.pack("!I", 123) +                                  # message id
            struct.pack("!H", len("hello".encode("utf-8"))) + b"hello" +# length and content of message
            struct.pack("!B", 0) +                                    # read flag (0 for False)
            struct.pack("!I", 1610000000)                             # timestamp
        )
        result = encode_conversation_data(data)
        self.assertEqual(result, expected)

    def test_encode_unread_data(self):
        # Prepare sample unread messages data.
        msg = {"id": 456, "from": "alice", "content": "hi there", "read": False, "timestamp": 1610000100}
        data = {
            "total_unread": 2,
            "remaining_unread": 1,
            "read_messages": [msg]
        }
        sender_bytes = "alice".encode("utf-8")
        content_bytes = "hi there".encode("utf-8")
        expected = (
            struct.pack("!BII", 0, 2, 1) +                          # flag (0), total_unread, remaining_unread
            struct.pack("!H", 1) +                                   # number of messages
            struct.pack("!I", 456) +                                 # message id
            struct.pack("!H", len(sender_bytes)) + sender_bytes +    # sender length and bytes
            struct.pack("!H", len(content_bytes)) + content_bytes +   # content length and bytes
            struct.pack("!B", 0) +                                   # read flag
            struct.pack("!I", 1610000100)                            # timestamp
        )
        result = encode_unread_data(data)
        self.assertEqual(result, expected)

    def test_encode_response_bin(self):
        # Test parameters.
        success = True
        message = "OK"
        data_bytes = b"DATA"
        op_code = 5
        success_byte = 1  # since success is True
        message_bytes = message.encode("utf-8")
        # Build payload: success flag, length of message, message bytes, length of data_bytes, then data_bytes.
        payload = (
            struct.pack(f"!B H {len(message_bytes)}s H", success_byte, len(message_bytes), message_bytes, len(data_bytes))
            + data_bytes
        )
        header = struct.pack("!BBH", VERSION, op_code, len(payload))
        expected = header + payload
        result = encode_response_bin(success, message, data_bytes, op_code)
        self.assertEqual(result, expected)

    def test_encode_event(self):
        # Test parameters.
        event_type = 0
        data_bytes = b"EVENT"
        payload = struct.pack("!B", event_type) + data_bytes
        header = struct.pack("!BBH", VERSION, 0, len(payload))
        expected = header + payload
        result = encode_event(event_type, data_bytes)
        self.assertEqual(result, expected)

    def test_encode_new_message_event(self):
        # Sample new message event data.
        data = {"id": 789, "from": "carol", "content": "hi", "timestamp": 1610000200}
        sender_bytes = "carol".encode("utf-8")
        content_bytes = "hi".encode("utf-8")
        fmt = f"!I H{len(sender_bytes)}s H{len(content_bytes)}s I"
        expected = struct.pack(fmt, 789, len(sender_bytes), sender_bytes, len(content_bytes), content_bytes, 1610000200)
        result = encode_new_message_event(data)
        self.assertEqual(result, expected)

    def test_encode_delete_message_event(self):
        # Sample delete message event data.
        data = {"message_ids": [101, 202, 303]}
        count = len(data["message_ids"])
        fmt = f"!B{count}I"
        expected = struct.pack(fmt, count, *data["message_ids"])
        result = encode_delete_message_event(data)
        self.assertEqual(result, expected)

    def test_decode_message_from_buffer_login(self):
        # Build a LOGIN buffer.
        username = "testuser"
        password_hash = "abc123"
        username_bytes = username.encode("utf-8")
        password_bytes = password_hash.encode("utf-8")
        buffer = (
            struct.pack("!BB", VERSION, OP_CODES_DICT["LOGIN"]) +
            struct.pack("!H", len(username_bytes)) + username_bytes +
            struct.pack("!H", len(password_bytes)) + password_bytes
        )
        req, consumed = decode_message_from_buffer(buffer)
        expected_req = {
            "opcode": OP_CODES_DICT["LOGIN"],
            "action": "LOGIN",
            "username": username,
            "password_hash": password_hash
        }
        self.assertEqual(req, expected_req)
        self.assertEqual(consumed, len(buffer))

    def test_decode_message_from_buffer_delete_account(self):
        # DELETE_ACCOUNT has only 2 header bytes.
        buffer = struct.pack("!BB", VERSION, OP_CODES_DICT["DELETE_ACCOUNT"])
        req, consumed = decode_message_from_buffer(buffer)
        expected_req = {"opcode": OP_CODES_DICT["DELETE_ACCOUNT"], "action": "DELETE_ACCOUNT"}
        self.assertEqual(req, expected_req)
        self.assertEqual(consumed, 2)

    def test_decode_message_from_buffer_list_accounts(self):
        # Build LIST_ACCOUNTS buffer.
        page_size = 10
        page_num = 2
        pattern = "a*"
        pattern_bytes = pattern.encode("utf-8")
        header_part = struct.pack("!BB", VERSION, OP_CODES_DICT["LIST_ACCOUNTS"])
        extra = struct.pack("!HHH", page_size, page_num, len(pattern_bytes))
        buffer = header_part + extra + pattern_bytes
        req, consumed = decode_message_from_buffer(buffer)
        expected_req = {
            "opcode": OP_CODES_DICT["LIST_ACCOUNTS"],
            "action": "LIST_ACCOUNTS",
            "page_size": page_size,
            "page_num": page_num,
            "pattern": pattern
        }
        self.assertEqual(req, expected_req)
        self.assertEqual(consumed, 8 + len(pattern_bytes))

    def test_decode_message_from_buffer_send_message(self):
        # Build SEND_MESSAGE buffer.
        recipient = "bob"
        content = "hello"
        recipient_bytes = recipient.encode("utf-8")
        content_bytes = content.encode("utf-8")
        header_part = struct.pack("!BB", VERSION, OP_CODES_DICT["SEND_MESSAGE"])
        buffer = (
            header_part +
            struct.pack("!H", len(recipient_bytes)) + recipient_bytes +
            struct.pack("!H", len(content_bytes)) + content_bytes
        )
        req, consumed = decode_message_from_buffer(buffer)
        expected_req = {
            "opcode": OP_CODES_DICT["SEND_MESSAGE"],
            "action": "SEND_MESSAGE",
            "to": recipient,
            "content": content
        }
        self.assertEqual(req, expected_req)
        self.assertEqual(consumed, len(buffer))

    def test_decode_message_from_buffer_read_messages_without_partner(self):
        # Build READ_MESSAGES buffer without chat partner (flag 0).
        page_size = 5
        page_num = 1
        flag = 0
        header_part = struct.pack("!BB", VERSION, OP_CODES_DICT["READ_MESSAGES"])
        buffer = header_part + struct.pack("!HHB", page_size, page_num, flag)
        req, consumed = decode_message_from_buffer(buffer)
        expected_req = {
            "opcode": OP_CODES_DICT["READ_MESSAGES"],
            "action": "READ_MESSAGES",
            "page_size": page_size,
            "page_num": page_num
        }
        self.assertEqual(req, expected_req)
        self.assertEqual(consumed, 7)

    def test_decode_message_from_buffer_read_messages_with_partner(self):
        # Build READ_MESSAGES buffer with chat partner (flag 1).
        page_size = 5
        page_num = 1
        flag = 1
        partner = "alice"
        partner_bytes = partner.encode("utf-8")
        header_part = struct.pack("!BB", VERSION, OP_CODES_DICT["READ_MESSAGES"])
        buffer = (
            header_part +
            struct.pack("!HHB", page_size, page_num, flag) +
            struct.pack("!H", len(partner_bytes)) + partner_bytes
        )
        req, consumed = decode_message_from_buffer(buffer)
        expected_req = {
            "opcode": OP_CODES_DICT["READ_MESSAGES"],
            "action": "READ_MESSAGES",
            "page_size": page_size,
            "page_num": page_num,
            "chat_partner": partner
        }
        self.assertEqual(req, expected_req)
        self.assertEqual(consumed, 7 + 2 + len(partner_bytes))

    def test_decode_message_from_buffer_delete_message(self):
        # Build DELETE_MESSAGE buffer.
        message_ids = [111, 222]
        count = len(message_ids)
        header_part = struct.pack("!BB", VERSION, OP_CODES_DICT["DELETE_MESSAGE"])
        buffer = (
            header_part +
            struct.pack("!B", count) +
            struct.pack("!II", *message_ids)
        )
        req, consumed = decode_message_from_buffer(buffer)
        expected_req = {
            "opcode": OP_CODES_DICT["DELETE_MESSAGE"],
            "action": "DELETE_MESSAGE",
            "message_ids": message_ids
        }
        self.assertEqual(req, expected_req)
        self.assertEqual(consumed, 2 + 1 + count * 4)

    def test_decode_message_from_buffer_check_username(self):
        # Build CHECK_USERNAME buffer.
        username = "dave"
        username_bytes = username.encode("utf-8")
        header_part = struct.pack("!BB", VERSION, OP_CODES_DICT["CHECK_USERNAME"])
        buffer = header_part + struct.pack("!H", len(username_bytes)) + username_bytes
        req, consumed = decode_message_from_buffer(buffer)
        expected_req = {
            "opcode": OP_CODES_DICT["CHECK_USERNAME"],
            "action": "CHECK_USERNAME",
            "username": username
        }
        self.assertEqual(req, expected_req)
        self.assertEqual(consumed, 2 + 2 + len(username_bytes))

    def test_decode_message_from_buffer_quit(self):
        # Build QUIT buffer.
        buffer = struct.pack("!BB", VERSION, OP_CODES_DICT["QUIT"])
        req, consumed = decode_message_from_buffer(buffer)
        expected_req = {
            "opcode": OP_CODES_DICT["QUIT"],
            "action": "QUIT"
        }
        self.assertEqual(req, expected_req)
        self.assertEqual(consumed, 2)

if __name__ == "__main__":
    unittest.main()
