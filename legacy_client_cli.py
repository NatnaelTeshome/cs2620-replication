import socket
import threading
import json
import struct
import hashlib
from getpass import getpass

def send_msg(s, data):
    """
    send data over a socket using a 4-byte length prefix.
    """
    msg = struct.pack("!I", len(data)) + data
    s.sendall(msg)

def recvall(s, n):
    """
    receive exactly n bytes from the socket.
    """
    data = b""
    while len(data) < n:
        packet = s.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_msg(s):
    """
    receive a message from the socket framed with a 4-byte header.
    """
    raw_len = recvall(s, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    return recvall(s, msg_len)

def receive_thread(s):
    """
    background thread to process incoming server messages.
    """
    while True:
        data = recv_msg(s)
        if not data:
            print("disconnected from server")
            break
        try:
            message = json.loads(data.decode("utf-8"))
        except:
            continue
        # handle asynchronous incoming messages
        if "command" in message and message["command"] == "incoming_message":
            sender = message["data"].get("sender")
            text = message["data"].get("message")
            print(f"\nincoming message from {sender}: {text}\n> ", end="")
        else:
            print(f"\nserver response: {message}\n> ", end="")

def hash_password(pwd):
    """
    hash password using sha256.
    """
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()

def main():
    host = "localhost"
    port = 9999
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print("connected to server")
    username = None
    # start a background thread to listen for incoming messages
    thread = threading.Thread(target=receive_thread, args=(s,), daemon=True)
    thread.start()
    while True:
        cmd = input("> ").strip()
        if cmd == "exit":
            break
        elif cmd == "create":
            username = input("username: ").strip()
            pwd = getpass("password: ").strip()
            pwd_hash = hash_password(pwd)
            request = {"command": "create_account",
                       "data": {"username": username,
                                "password_hash": pwd_hash}}
            send_msg(s, json.dumps(request).encode("utf-8"))
        elif cmd == "login":
            username = input("username: ").strip()
            pwd = getpass("password: ").strip()
            pwd_hash = hash_password(pwd)
            request = {"command": "login",
                       "data": {"username": username,
                                "password_hash": pwd_hash}}
            send_msg(s, json.dumps(request).encode("utf-8"))
        elif cmd == "send":
            if not username:
                print("you must login first")
                continue
            recipient = input("recipient: ").strip()
            text = input("message: ").strip()
            request = {"command": "send_message",
                       "data": {"sender": username,
                                "recipient": recipient,
                                "message": text}}
            send_msg(s, json.dumps(request).encode("utf-8"))
        elif cmd == "read":
            if not username:
                print("you must login first")
                continue
            count_input = input("number of messages (0 for all): ").strip()
            try:
                count = int(count_input)
            except:
                count = 0
            request = {"command": "read_messages",
                       "data": {"username": username,
                                "count": count}}
            send_msg(s, json.dumps(request).encode("utf-8"))
        else:
            print("unknown command, use: create, login, send, read, exit")
    s.close()

if __name__ == "__main__":
    main()

