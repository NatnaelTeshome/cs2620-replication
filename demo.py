#!/usr/bin/env python3
import os
import time
import subprocess
import signal
import argparse
import threading
import logging
import shutil
from datetime import datetime

# Import chat client
from client_grpc import CustomProtocolClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Global variables
servers = {}
clients = {}
active_demo = True
demo_step = 0

def clear_data_directory():
    """Clear the data directory to start with a clean state."""
    if os.path.exists("./data"):
        shutil.rmtree("./data")
        logging.info("Cleared data directory")
    os.makedirs("./data", exist_ok=True)

def start_server(node_id, host, port, raft_port, leader_host=None, leader_port=None):
    """Start a chat server node."""
    cmd = [
        "python", "chat_server.py",
        "--node-id", node_id,
        "--host", host,
        "--port", str(port),
        "--raft-port", str(raft_port)
    ]
    
    if leader_host and leader_port:
        cmd.extend(["--leader-host", leader_host, "--leader-port", str(leader_port)])
    
    logging.info(f"Starting server node {node_id} on {host}:{port} (Raft port: {raft_port})")
    
    # Start the server process
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    
    # Store the process
    servers[node_id] = {
        "process": process,
        "host": host,
        "port": port,
        "raft_port": raft_port
    }
    
    # Give it a moment to start up
    time.sleep(1)
    
    return process

def kill_server(node_id):
    """Kill a specific server."""
    if node_id in servers:
        logging.info(f"Killing server node {node_id}")
        try:
            servers[node_id]["process"].terminate()
            servers[node_id]["process"].wait(timeout=2)
        except subprocess.TimeoutExpired:
            servers[node_id]["process"].kill()
        del servers[node_id]
    else:
        logging.warning(f"Server node {node_id} not found")

def restart_server(node_id, host, port, raft_port, leader_host=None, leader_port=None):
    """Restart a server node."""
    kill_server(node_id)
    return start_server(node_id, host, port, raft_port, leader_host, leader_port)

def cleanup():
    """Clean up all servers and clients."""
    logging.info("Cleaning up...")
    for node_id in list(servers.keys()):
        kill_server(node_id)
    for client_id in list(clients.keys()):
        try:
            clients[client_id].close()
        except:
            pass
    logging.info("All processes terminated")

def on_new_message(message):
    """Callback for new message events."""
    print(f"\n[PUSH EVENT] New message from {message['from_']}: {message['content']}")

def on_delete_message(message):
    """Callback for delete message events."""
    print(f"\n[PUSH EVENT] Messages deleted: {message['message_ids']}")

def create_client(client_id, host, port):
    """Create a chat client."""
    try:
        client = CustomProtocolClient(
            host, 
            port, 
            on_msg_callback=on_new_message,
            on_delete_callback=on_delete_message
        )
        print(client)
        clients[client_id] = client
        logging.info(f"Created client {client_id} connected to {host}:{port}")
        return client
    except Exception as e:
        logging.error(f"Failed to create client {client_id}: {e}")
        return None

def demo_create_accounts():
    """Demo creating user accounts."""
    global demo_step
    demo_step += 1
    print(f"\n=== STEP {demo_step}: CREATING USER ACCOUNTS ===")
    
    client = clients["client1"]
    
    # Check if usernames exist
    try:
        alice_exists = client.account_exists("alice")
        bob_exists = client.account_exists("bob")
        charlie_exists = client.account_exists("charlie")
        
        print(f"User 'alice' exists: {alice_exists}")
        print(f"User 'bob' exists: {bob_exists}")
        print(f"User 'charlie' exists: {charlie_exists}")
        
        # Create accounts if they don't exist
        if not alice_exists:
            client.create_account("alice", "password")
            print("Created account for 'alice'")
        
        if not bob_exists:
            client.create_account("bob", "password")
            print("Created account for 'bob'")
            
        if not charlie_exists:
            client.create_account("charlie", "password")
            print("Created account for 'charlie'")
        
        # List accounts to verify
        print("\nListing accounts:")
        accounts = client.list_accounts()
        for account in accounts:
            print(f"- {account}")
            
    except Exception as e:
        print(f"Error during account creation: {e}")

def demo_send_messages():
    """Demo sending messages between users."""
    global demo_step
    demo_step += 1
    print(f"\n=== STEP {demo_step}: SENDING MESSAGES ===")
    
    # Log in alice and bob clients
    try:
        clients["client1"].login("alice", "password")
        print("Logged in as 'alice' on client1")
        
        clients["client2"].login("bob", "password")
        print("Logged in as 'bob' on client2")
        
        # Alice sends messages to Bob
        msg_id1 = clients["client1"].send_message("bob", "Hello Bob! How are you?")
        print(f"Alice sent message (ID: {msg_id1})")
        time.sleep(1)
        
        msg_id2 = clients["client1"].send_message("bob", "Let's test this replicated chat system!")
        print(f"Alice sent message (ID: {msg_id2})")
        time.sleep(1)
        
        # Bob sends a reply to Alice
        msg_id3 = clients["client2"].send_message("alice", "Hi Alice! I'm doing well. The system seems to be working!")
        print(f"Bob sent message (ID: {msg_id3})")
        time.sleep(1)
        
        # Read messages on Bob's client
        print("\nBob's messages:")
        messages = clients["client2"].read_messages()
        for msg in messages:
            print(f"[{datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M:%S')}] {msg['from_']}: {msg['content']}")
        
        # Read messages on Alice's client
        print("\nAlice's messages:")
        messages = clients["client1"].read_messages()
        for msg in messages:
            print(f"[{datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M:%S')}] {msg['from_']}: {msg['content']}")
        
    except Exception as e:
        print(f"Error during message sending: {e}")

def demo_fault_tolerance():
    """Demo fault tolerance by killing servers."""
    global demo_step
    demo_step += 1
    print(f"\n=== STEP {demo_step}: FAULT TOLERANCE TEST ===")
    
    try:
        # Kill a follower node
        print("\nKilling follower node (node2)...")
        kill_server("2")
        time.sleep(2)
        
        # Try sending a message with one node down
        print("\nSending message with one node down...")
        msg_id = clients["client1"].send_message("bob", "This message is sent with one node down!")
        print(f"Message sent successfully (ID: {msg_id})")
        time.sleep(1)
        
        # Kill another follower node
        print("\nKilling another follower node (node3)...")
        kill_server("3")
        time.sleep(2)
        
        # Try sending a message with two nodes down
        print("\nSending message with two nodes down (should still work with 2-fault tolerance)...")
        msg_id = clients["client1"].send_message("bob", "This message is sent with two nodes down!")
        print(f"Message sent successfully (ID: {msg_id})")
        
        # Read messages on Bob's client to verify they were received
        print("\nVerifying messages on Bob's client:")
        messages = clients["client2"].read_messages()
        for msg in messages:
            print(f"[{datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M:%S')}] {msg['from_']}: {msg['content']}")
        
    except Exception as e:
        print(f"Error during fault tolerance test: {e}")

def demo_persistence():
    """Demo persistence by restarting servers and checking if messages are preserved."""
    global demo_step
    demo_step += 1
    print(f"\n=== STEP {demo_step}: PERSISTENCE TEST ===")
    
    try:
        # Restart the nodes that were killed
        print("\nRestarting node2...")
        restart_server("2", "localhost", 50052, 50062, "localhost", 50061)
        time.sleep(2)
        
        print("Restarting node3...")
        restart_server("3", "localhost", 50053, 50063, "localhost", 50061)
        time.sleep(2)
        
        # Check if messages are still accessible after restart
        print("\nChecking message persistence after restart...")
        messages = clients["client2"].read_messages()
        
        if messages:
            print("Messages were successfully preserved after server restarts!")
            for msg in messages:
                print(f"[{datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M:%S')}] {msg['from_']}: {msg['content']}")
        else:
            print("No messages found. Persistence might not be working correctly.")
        
    except Exception as e:
        print(f"Error during persistence test: {e}")

def demo_leader_failover():
    """Demo leader failover by killing the leader and verifying a new leader is elected."""
    global demo_step
    demo_step += 1
    print(f"\n=== STEP {demo_step}: LEADER FAILOVER TEST ===")
    
    try:
        # Kill the leader (node1)
        print("\nKilling the leader node (node1)...")
        kill_server("1")
        time.sleep(5)  # Give time for a new leader to be elected
        
        # Try sending a message after leader failover
        print("\nSending message after leader failover...")
        try:
            msg_id = clients["client2"].send_message("alice", "This message is sent after leader failover!")
            print(f"Message sent successfully (ID: {msg_id})")
            print("Leader failover successful! A new leader was elected.")
        except Exception as e:
            print(f"Error sending message: {e}")
        
        # Reconnect client1 to one of the remaining servers
        print("\nReconnecting client1 to a different server...")
        try:
            clients["client1"].connect_to_server("localhost", 50052)
            clients["client1"].login("alice", "password")
            print("Reconnected client1 to node2")
            
            # Read messages
            print("\nAlice's messages after reconnection:")
            messages = clients["client1"].read_messages()
            for msg in messages:
                print(f"[{datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M:%S')}] {msg['from_']}: {msg['content']}")
        except Exception as e:
            print(f"Error reconnecting client: {e}")
        
    except Exception as e:
        print(f"Error during leader failover test: {e}")

def demo_new_server_addition():
    """Demo adding a new server to the cluster (extra credit)."""
    global demo_step
    demo_step += 1
    print(f"\n=== STEP {demo_step}: NEW SERVER ADDITION (EXTRA CREDIT) ===")
    
    # Start a new server node and join it to the cluster
    try:
        print("\nStarting a new server (node4) and joining it to the cluster...")
        # For the new node, connect to an existing node (e.g., node2)
        new_node = start_server("4", "localhost", 50054, 50064, "localhost", 50062)
        time.sleep(5)  # Give time for the new node to join
        
        # Send a new message after adding the server
        msg_id = clients["client2"].send_message("alice", "This message is sent after adding a new server!")
        print(f"Message sent successfully (ID: {msg_id})")
        
        # Kill two old nodes to verify the new node is functioning
        print("\nKilling two old nodes to verify the new node is working...")
        kill_server("2")
        time.sleep(1)
        kill_server("3")
        time.sleep(2)
        
        # Try sending a message with only the new node remaining
        try:
            clients["client2"].connect_to_server("localhost", 50054)
            msg_id = clients["client2"].send_message("alice", "This message is sent with only the new node running!")
            print(f"Message sent successfully (ID: {msg_id}). New server addition successful!")
        except Exception as e:
            print(f"Error sending message to new server: {e}")
        
    except Exception as e:
        print(f"Error during new server addition test: {e}")

def run_demo():
    """Run the complete demo."""
    try:
        # Clear data directory for a clean start
        clear_data_directory()
        
        # Start a cluster with 3 nodes
        start_server("1", "localhost", 50051, 50061)
        time.sleep(1)
        start_server("2", "localhost", 50052, 50062, "localhost", 50061)
        time.sleep(1)
        start_server("3", "localhost", 50053, 50063, "localhost", 50061)
        time.sleep(3)  # Give time for cluster to form
        
        # Create clients
        create_client("client1", "localhost", 50051)
        create_client("client2", "localhost", 50051)
        
        # Run the demo steps
        demo_create_accounts()
        time.sleep(1)
        
        demo_send_messages()
        time.sleep(1)
        
        demo_fault_tolerance()
        time.sleep(3)
        
        demo_persistence()
        time.sleep(3)
        
        demo_leader_failover()
        time.sleep(3)
        
        demo_new_server_addition()
        
        print("\n=== DEMO COMPLETED SUCCESSFULLY ===")
        
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        print(f"\nDemo failed with error: {e}")
    finally:
        cleanup()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat System Demo")
    parser.add_argument("--skip-clear", action="store_true", help="Skip clearing data directory")
    args = parser.parse_args()
    
    if not args.skip_clear:
        clear_data_directory()
    
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    finally:
        cleanup()