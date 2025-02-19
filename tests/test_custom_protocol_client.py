import struct
import socket
import pytest
import time

from client_custom_wp import (
    VERSION,
    OP_CODES_DICT,
    EVENT_NEW_MESSAGE,
    EVENT_DELETE_MESSAGE,
    encode_login,
    encode_create_account,
    encode_delete_account,
    encode_list_accounts,
    encode_send_message,
    encode_read_messages,
    encode_delete_message,
    encode_check_username,
    encode_quit,
    decode_data_bytes,
    decode_push_event,
    _decode_response_payload,
    CustomProtocolClient,
)

##############################################
# Fake Socket classes to avoid real networking
##############################################


class FakeSocket:
    """A fake socket that does nothing but record sent data."""

    def __init__(self, *args, **kwargs):
        self.sent_data = b""
        self.closed = False

    def connect(self, addr):
        self.addr = addr

    def sendall(self, data):
        self.sent_data += data

    def recv(self, bufsize):
        time.sleep(0.01)
        return b""

    def close(self):
        self.closed = True


class FakeSocketForClose:
    """A fake socket used to test close()."""

    def __init__(self, *args, **kwargs):
        self.closed = False

    def sendall(self, data):
        pass

    def close(self):
        self.closed = True


##############################################
# Fixtures for the CustomProtocolClient tests
##############################################


@pytest.fixture
def cp_client(monkeypatch):
    """
    Create a CustomProtocolClient that uses a FakeSocket so that no real connection is made.
    Also, disable the listener thread.
    """
    # Override socket.socket so that any new socket is a FakeSocket.
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: FakeSocket())
    client_obj = CustomProtocolClient("localhost", 12345)
    monkeypatch.setattr(client_obj, "_listen", lambda: None)
    return client_obj


##############################################
# Tests for encoder helper functions
##############################################


def test_encode_login():
    payload = {"username": "alice", "password": "secret"}
    encoded = encode_login(payload)
    # Check that the first two bytes are version and op-code for LOGIN.
    version, opcode = struct.unpack("!BB", encoded[:2])
    assert version == VERSION
    assert opcode == OP_CODES_DICT["LOGIN"]
    uname_len = struct.unpack("!H", encoded[2:4])[0]
    assert uname_len == len("alice".encode("utf-8"))


def test_encode_create_account():
    payload = {"username": "bob", "password": "abc"}
    encoded = encode_create_account(payload)
    version, opcode = struct.unpack("!BB", encoded[:2])
    assert version == VERSION
    assert opcode == OP_CODES_DICT["CREATE_ACCOUNT"]


def test_encode_delete_account():
    encoded = encode_delete_account({})
    version, opcode = struct.unpack("!BB", encoded)
    assert version == VERSION
    assert opcode == OP_CODES_DICT["DELETE_ACCOUNT"]


def test_encode_list_accounts():
    payload = {"page_size": 10, "page_num": 2, "pattern": "al*"}
    encoded = encode_list_accounts(payload)
    # The format string "!BBHHH" expects 8 bytes.
    version, opcode, ps, pn, pat_len = struct.unpack("!BBHHH", encoded[:8])
    assert version == VERSION
    assert opcode == OP_CODES_DICT["LIST_ACCOUNTS"]
    assert ps == 10
    assert pn == 2
    pattern = struct.unpack(f"!{pat_len}s", encoded[8 : 8 + pat_len])[0].decode("utf-8")
    assert pattern == "al*"


def test_encode_send_message():
    payload = {"to": "bob", "message": "Hello!"}
    encoded = encode_send_message(payload)
    version, opcode = struct.unpack("!BB", encoded[:2])
    assert version == VERSION
    assert opcode == OP_CODES_DICT["SEND_MESSAGE"]


def test_encode_read_messages():
    payload = {"page_size": 5, "page_num": 1, "chat_partner": "charlie"}
    encoded = encode_read_messages(payload)
    base = struct.unpack("!BBHHB", encoded[:7])
    assert base[0] == VERSION
    assert base[1] == OP_CODES_DICT["READ_MESSAGES"]
    assert base[2] == 5
    assert base[3] == 1
    assert base[4] == 1  # flag indicating partner provided

    payload2 = {"page_size": 5, "page_num": 1}
    encoded2 = encode_read_messages(payload2)
    base2 = struct.unpack("!BBHHB", encoded2[:7])
    assert base2[4] == 0


def test_encode_delete_message():
    payload = {"message_ids": [101, 202]}
    encoded = encode_delete_message(payload)
    version, opcode, count = struct.unpack("!BBB", encoded[:3])
    assert version == VERSION
    assert opcode == OP_CODES_DICT["DELETE_MESSAGE"]
    assert count == 2


def test_encode_check_username():
    payload = {"username": "dave"}
    encoded = encode_check_username(payload)
    version, opcode = struct.unpack("!BB", encoded[:2])
    assert version == VERSION
    assert opcode == OP_CODES_DICT["CHECK_USERNAME"]


def test_encode_quit():
    encoded = encode_quit()
    version, opcode = struct.unpack("!BB", encoded)
    assert version == VERSION
    assert opcode == OP_CODES_DICT["QUIT"]


##############################################
# Tests for decoder helper functions
##############################################


def test_decode_data_bytes_list_accounts():
    total = 3
    accounts_list = [b"alice", b"bob"]
    account_count = len(accounts_list)
    parts = []
    for name in accounts_list:
        parts.append(struct.pack("!H", len(name)) + name)
    data_bytes = (
        struct.pack("!I", total) + struct.pack("!H", account_count) + b"".join(parts)
    )
    result = decode_data_bytes(data_bytes, opcode=OP_CODES_DICT["LIST_ACCOUNTS"])
    assert result["total_accounts"] == total
    assert result["accounts"] == ["alice", "bob"]


def test_decode_push_event_new_message():
    msg_id = 555
    sender = "eve".encode("utf-8")
    content = "Hi there".encode("utf-8")
    ts = 1234567890
    fmt = f"!B I H{len(sender)}s H{len(content)}s I"
    payload = struct.pack(
        fmt, EVENT_NEW_MESSAGE, msg_id, len(sender), sender, len(content), content, ts
    )
    result = decode_push_event(payload)
    assert result["event"] == "NEW_MESSAGE"
    data = result["data"]
    assert data["id"] == msg_id
    assert data["from"] == "eve"
    assert data["content"] == "Hi there"
    assert data["timestamp"] == ts


def test_decode_push_event_delete_message():
    message_ids = [111, 222]
    count = len(message_ids)
    fmt = "!B B" + "I" * count
    payload = struct.pack(fmt, EVENT_DELETE_MESSAGE, count, *message_ids)
    result = decode_push_event(payload)
    assert result["event"] == "DELETE_MESSAGE"
    assert result["data"]["message_ids"] == message_ids


def test__decode_response_payload():
    success = 1
    message = "OK".encode("utf-8")
    data_bytes = struct.pack("!I", 999)
    payload = (
        struct.pack("!B H", success, len(message))
        + message
        + struct.pack("!H", len(data_bytes))
        + data_bytes
    )
    result = _decode_response_payload(payload, opcode=OP_CODES_DICT["SEND_MESSAGE"])
    assert result["success"] is True
    assert result["message"] == "OK"
    assert result["data"]["id"] == 999


##############################################
# Tests for CustomProtocolClient API methods
##############################################


def test_cp_login_success(monkeypatch, cp_client):
    def fake_send_request(payload):
        return {"success": True, "message": "Logged in as alice"}

    monkeypatch.setattr(cp_client, "_send_request", fake_send_request)
    msg = cp_client.login("alice", "secret")
    assert "alice" in msg
    assert cp_client.username == "alice"


def test_cp_create_account(monkeypatch, cp_client):
    def fake_send_request(payload):
        return {"success": True, "message": "Account created"}

    monkeypatch.setattr(cp_client, "_send_request", fake_send_request)
    cp_client.create_account("bob", "pass")
    assert cp_client.username == "bob"


def test_cp_delete_account(monkeypatch, cp_client):
    cp_client.username = "charlie"

    def fake_send_request(payload):
        return {"success": True, "message": "Account deleted"}

    monkeypatch.setattr(cp_client, "_send_request", fake_send_request)
    cp_client.delete_account()
    assert cp_client.username is None


def test_cp_list_accounts(monkeypatch, cp_client):
    def fake_send_request(payload):
        return {
            "success": True,
            "message": "Listed",
            "data": {"accounts": ["alice", "bob"]},
        }

    monkeypatch.setattr(cp_client, "_send_request", fake_send_request)
    lst = cp_client.list_accounts(pattern="a")
    assert lst == ["alice", "bob"]


def test_cp_send_message(monkeypatch, cp_client):
    cp_client.username = "alice"

    def fake_send_request(payload):
        return {"success": True, "message": "Sent", "data": {"id": 123}}

    monkeypatch.setattr(cp_client, "_send_request", fake_send_request)
    msg_id = cp_client.send_message("bob", "Hello!")
    assert msg_id == 123


def test_cp_read_messages(monkeypatch, cp_client):
    def fake_send_request(payload):
        return {
            "success": True,
            "message": "Read",
            "data": {"read_messages": [{"id": 1}, {"id": 2}]},
        }

    monkeypatch.setattr(cp_client, "_send_request", fake_send_request)
    msgs = cp_client.read_messages()
    assert isinstance(msgs, list)
    assert len(msgs) == 2

    def fake_send_request_chat(payload):
        return {"success": True, "message": "Read", "data": {"messages": [{"id": 3}]}}

    monkeypatch.setattr(cp_client, "_send_request", fake_send_request_chat)
    msgs_chat = cp_client.read_messages(to_user="dave")
    assert len(msgs_chat) == 1
    assert msgs_chat[0]["id"] == 3


def test_cp_delete_message(monkeypatch, cp_client):
    def fake_send_request(payload):
        return {"success": True, "message": "Deleted"}

    monkeypatch.setattr(cp_client, "_send_request", fake_send_request)
    cp_client.delete_message(321)


def test_cp_account_exists(monkeypatch, cp_client):
    def fake_send_request(payload):
        if payload.get("username") == "alice":
            return {"success": True, "message": "exists"}
        else:
            return {"success": False, "message": "not exists"}

    monkeypatch.setattr(cp_client, "_send_request", fake_send_request)
    assert cp_client.account_exists("alice") is True
    assert cp_client.account_exists("zach") is False


def test_cp_close(monkeypatch, cp_client):
    fake_sock = FakeSocketForClose()
    cp_client.sock = fake_sock
    cp_client.close()
    assert fake_sock.closed is True


def test_cp_handle_push_event(monkeypatch):
    on_msg_called = False
    on_del_called = False
    new_msg = {"id": 50, "from": "eve", "content": "Hi", "timestamp": 1111}
    del_msg = {"message_ids": [50]}

    def on_msg(data):
        nonlocal on_msg_called
        on_msg_called = True
        assert data == new_msg

    def on_del(data):
        nonlocal on_del_called
        on_del_called = True
        assert data == del_msg

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: FakeSocket())
    client_obj = CustomProtocolClient(
        "localhost", 12345, on_msg_callback=on_msg, on_delete_callback=on_del
    )
    monkeypatch.setattr(client_obj, "_listen", lambda: None)
    client_obj.handle_push_event({"event": "NEW_MESSAGE", "data": new_msg})
    client_obj.handle_push_event({"event": "DELETE_MESSAGE", "data": del_msg})
    assert on_msg_called is True
    assert on_del_called is True
