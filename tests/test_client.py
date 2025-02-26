import time
import pytest
import hashlib
import socket
import os
import sys
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(parent_dir)
from client import JSONClient, MockClient


class FakeSocket:
    """A fake socket that doesn’t actually perform network I/O."""

    def __init__(self, *args, **kwargs):
        self.sent_data = b""
        self.closed = False

    def connect(self, addr):
        # Simply record the address; do not attempt a real connection.
        self.address = addr

    def sendall(self, data):
        self.sent_data += data

    def recv(self, bufsize):
        # Return empty bytes (simulate no incoming data)
        time.sleep(0.01)
        return b""

    def close(self):
        self.closed = True


class FakeSocketForClose:
    """A fake socket used to test the close() method."""

    def __init__(self, *args, **kwargs):
        self.closed = False

    def sendall(self, data):
        pass

    def close(self):
        self.closed = True


@pytest.fixture
def json_client(monkeypatch):
    """
    Fixture that creates a JSONClient instance but overrides the
    socket.socket call so no real connection is attempted.
    """
    # Patch socket.socket so that it returns our FakeSocket.
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: FakeSocket())
    # Create a JSONClient; the connect() call now uses our FakeSocket.
    client_obj = JSONClient("localhost", 12345)
    # Override the listener thread so it doesn’t interfere.
    monkeypatch.setattr(client_obj, "_listen", lambda: None)
    return client_obj


def test_hash_password(json_client):
    hashed = json_client._hash_password("password")
    expected = hashlib.sha256("password".encode("utf-8")).hexdigest()
    assert hashed == expected


def test_login_success(monkeypatch, json_client):
    def fake_send_request(payload):
        return {"success": True, "message": f"Logged in as {payload['username']}"}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request)
    msg = json_client.login("alice", "secret")
    assert "alice" in msg
    assert json_client.username == "alice"


def test_login_failure(monkeypatch, json_client):
    def fake_send_request(payload):
        return {"success": False, "message": "Login failed"}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request)
    with pytest.raises(Exception) as excinfo:
        json_client.login("alice", "secret")
    assert "Login failed" in str(excinfo.value)


def test_send_message(monkeypatch, json_client):
    json_client.username = "alice"  # Simulate that we're logged in.

    def fake_send_request(payload):
        return {"success": True, "data": {"id": 42}}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request)
    msg_id = json_client.send_message("bob", "Hello Bob")
    assert msg_id == 42


def test_account_exists(monkeypatch, json_client):
    def fake_send_request(payload):
        # Return success only if username is "alice"
        if payload.get("username") == "alice":
            return {"success": True}
        else:
            return {"success": False}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request)
    assert json_client.account_exists("alice") is True
    assert json_client.account_exists("bob") is False


def test_create_account(monkeypatch, json_client):
    def fake_send_request(payload):
        return {"success": True}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request)
    json_client.create_account("alice", "secret")
    assert json_client.username == "alice"


def test_list_accounts(monkeypatch, json_client):
    def fake_send_request(payload):
        return {"success": True, "data": {"accounts": ["alice", "bob"]}}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request)
    lst = json_client.list_accounts()
    assert lst == ["alice", "bob"]


def test_read_messages(monkeypatch, json_client):
    # Test reading without a chat partner.
    def fake_send_request(payload):
        return {"success": True, "data": {"read_messages": [{"id": 1}, {"id": 2}]}}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request)
    msgs = json_client.read_messages()
    assert isinstance(msgs, list)
    assert len(msgs) == 2

    # Test reading with a chat partner.
    def fake_send_request_chat(payload):
        return {"success": True, "data": {"messages": [{"id": 3}]}}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request_chat)
    msgs_chat = json_client.read_messages(to_user="bob")
    assert len(msgs_chat) == 1
    assert msgs_chat[0]["id"] == 3


def test_delete_message(monkeypatch, json_client):
    def fake_send_request(payload):
        return {"success": True}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request)
    # Should not raise an exception.
    json_client.delete_message(1)


def test_delete_account(monkeypatch, json_client):
    json_client.username = "alice"

    def fake_send_request(payload):
        return {"success": True}

    monkeypatch.setattr(json_client, "_send_request", fake_send_request)
    json_client.delete_account("alice")
    assert json_client.username is None


def test_close(json_client):
    fake_sock = FakeSocketForClose()
    json_client.sock = fake_sock
    json_client.close()
    assert fake_sock.closed is True
    assert json_client.running is False


def test_handle_push_event(monkeypatch):
    # Patch socket.socket so that JSONClient uses FakeSocket.
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: FakeSocket())
    on_msg_called = False
    on_delete_called = False
    new_msg_data = {"id": 1, "content": "Hello"}
    delete_data = {"id": 2, "content": "Bye"}

    def on_msg(data):
        nonlocal on_msg_called
        on_msg_called = True
        assert data == new_msg_data

    def on_delete(data):
        nonlocal on_delete_called
        on_delete_called = True
        assert data == delete_data

    # Create a client with callbacks.
    client_obj = JSONClient(
        "localhost", 12345, on_msg_callback=on_msg, on_delete_callback=on_delete
    )
    monkeypatch.setattr(client_obj, "_listen", lambda: None)
    client_obj.handle_push_event({"event": "NEW_MESSAGE", "data": new_msg_data})
    client_obj.handle_push_event({"event": "DELETE_MESSAGE", "data": delete_data})
    assert on_msg_called is True
    assert on_delete_called is True


###############################
# Tests for MockClient        #
###############################


def test_mock_client_account_exists():
    client_obj = MockClient("localhost", 12345)
    assert client_obj.account_exists("alice") is True
    assert client_obj.account_exists("nonexistent") is False


def test_mock_client_create_account():
    client_obj = MockClient("localhost", 12345)
    # "alice" already exists per the initial data.
    with pytest.raises(Exception) as excinfo:
        client_obj.create_account("alice", "newpass")
    assert "username taken" in str(excinfo.value)
    # Create a new account.
    client_obj.create_account("charlie", "pass")
    assert client_obj.username == "charlie"
    assert client_obj.accounts["charlie"] == "pass"


def test_mock_client_delete_account():
    client_obj = MockClient("localhost", 12345)
    client_obj.create_account("charlie", "pass")
    client_obj.delete_account("charlie")
    assert "charlie" not in client_obj.accounts


def test_mock_client_login():
    client_obj = MockClient("localhost", 12345)
    unread = client_obj.login("michal", "kurek")
    expected = len([m for m in client_obj.messages if m["to"] == "michal"])
    assert unread == expected
    assert client_obj.username == "michal"


def test_mock_client_list_accounts():
    client_obj = MockClient("localhost", 12345)
    lst = client_obj.list_accounts()
    for acct in ["alice", "bob", "natnael", "michal"]:
        assert acct in lst
    lst2 = client_obj.list_accounts(pattern="ali")
    assert lst2 == ["alice"]


def test_mock_client_read_messages():
    client_obj = MockClient("localhost", 12345)
    client_obj.username = "michal"
    msgs = client_obj.read_messages()
    expected = [
        m for m in client_obj.messages if m["to"] == "michal" or m["from"] == "michal"
    ]
    assert len(msgs) == len(expected)


def test_mock_client_send_message():
    client_obj = MockClient("localhost", 12345)
    client_obj.session_token = "dummy_token"
    client_obj.username = "alice"
    old_len = len(client_obj.messages)
    client_obj.send_message("bob", "Hello")
    assert len(client_obj.messages) == old_len + 1
    last_msg = client_obj.messages[-1]
    assert last_msg["from"] == "alice"
    assert last_msg["to"] == "bob"
    assert last_msg["content"] == "Hello"


def test_mock_client_delete_message():
    client_obj = MockClient("localhost", 12345)
    old_len = len(client_obj.messages)
    # Delete an existing message (assume id 1 exists per initial data).
    client_obj.delete_message(1)
    assert len(client_obj.messages) == old_len - 1
    with pytest.raises(Exception):
        client_obj.delete_message(999)  # non-existent message
