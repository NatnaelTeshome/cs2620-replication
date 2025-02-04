import socket
import threading
import json
import struct
import hashlib

# in‑memory store for accounts and messages
# accounts: username -> {"password": hashed, "messages": [message, ...]}
# online_users: username -> connection
accounts = {}
online_users = {}
lock = threading.Lock()

def send_msg(conn, data):
    """
    send data over a socket with a 4-byte length prefix.
    """
    msg = struct.pack("!I", len(data)) + data
    conn.sendall(msg)

def recvall(conn, n):
    """
    receive exactly n bytes from the socket.
    """
    data = b""
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_msg(conn):
    """
    receive a message from the socket framed with a 4-byte header.
    """
    raw_len = recvall(conn, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    return recvall(conn, msg_len)

def handle_client(conn, addr):
    """
    handle client connection in a dedicated thread.
    """
    print(f"accepted connection from {addr}")
    user = None
    try:
        while True:
            data = recv_msg(conn)
            if not data:
                break
            try:
                request = json.loads(data.decode("utf-8"))
            except Exception as e:
                send_msg(conn, json.dumps({"status": "error",
                                           "error": "invalid json"}).encode("utf-8"))
                continue
            command = request.get("command")
            content = request.get("data")
            if command == "create_account":
                username = content.get("username")
                pwd_hash = content.get("password_hash")
                with lock:
                    if username in accounts:
                        response = {"status": "error", "error": "account exists"}
                    else:
                        accounts[username] = {"password": pwd_hash, "messages": []}
                        response = {"status": "success", "message": "account created"}
                send_msg(conn, json.dumps(response).encode("utf-8"))
            elif command == "login":
                username = content.get("username")
                pwd_hash = content.get("password_hash")
                with lock:
                    if username not in accounts:
                        response = {"status": "error",
                                    "error": "account does not exist"}
                    elif accounts[username]["password"] != pwd_hash:
                        response = {"status": "error",
                                    "error": "incorrect password"}
                    else:
                        user = username
                        online_users[username] = conn
                        unread = len(accounts[username]["messages"])
                        response = {"status": "success",
                                    "message": f"{unread} unread messages"}
                send_msg(conn, json.dumps(response).encode("utf-8"))
            elif command == "send_message":
                sender = content.get("sender")
                recipient = content.get("recipient")
                msg_text = content.get("message")
                payload = {"sender": sender, "message": msg_text}
                with lock:
                    if recipient not in accounts:
                        response = {"status": "error",
                                    "error": "recipient does not exist"}
                    else:
                        if recipient in online_users:
                            try:
                                send_msg(online_users[recipient],
                                         json.dumps({"command": "incoming_message",
                                                     "data": payload}).encode("utf-8"))
                            except Exception as e:
                                accounts[recipient]["messages"].append(payload)
                        else:
                            accounts[recipient]["messages"].append(payload)
                        response = {"status": "success", "message": "message sent"}
                send_msg(conn, json.dumps(response).encode("utf-8"))
            elif command == "read_messages":
                username = content.get("username")
                count = content.get("count", 0)
                with lock:
                    if username not in accounts:
                        response = {"status": "error",
                                    "error": "account does not exist"}
                    else:
                        msgs = accounts[username]["messages"]
                        if count == 0 or count > len(msgs):
                            count = len(msgs)
                        msgs_to_send = msgs[:count]
                        accounts[username]["messages"] = msgs[count:]
                        response = {"status": "success", "messages": msgs_to_send}
                send_msg(conn, json.dumps(response).encode("utf-8"))
            else:
                response = {"status": "error", "error": "unknown command"}
                send_msg(conn, json.dumps(response).encode("utf-8"))
    except Exception as e:
        print(f"error with connection {addr}: {e}")
    finally:
        with lock:
            if user and user in online_users:
                del online_users[user]
        conn.close()
        print(f"connection from {addr} closed")

def main():
    # TODO: This will get us failed, I'm only doing this for prototyping
    host = "localhost"
    port = 9999

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(f"server listening on {host}:{port}")
    try:
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr),
                                      daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("server shutting down")
    finally:
        s.close()

if __name__ == "__main__":
    main() 
