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
import json
import socket # Needed for get_local_ip if not importing
from typing import Dict, Any, Optional, List, Tuple

# --- UI and Input Handling ---
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.prompt import Prompt

# --- Chat Client ---
from client_grpc import CustomProtocolClient

# --- Configuration ---
try:
    from config import get_local_ip
except ImportError:
    # Fallback if config.py or get_local_ip is not found
    def get_local_ip():
        """Get the non-localhost IP of the machine."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't need to be reachable
            s.connect(("10.255.255.255", 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = "127.0.0.1"
        finally:
            s.close()
        return IP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
# Suppress noisy logs if needed (e.g., from libraries)
# logging.getLogger("werkzeug").setLevel(logging.WARNING)

# --- Global Variables ---
console = Console()
local_servers: Dict[str, Dict[str, Any]] = {} # Servers running on this machine
clients: Dict[str, CustomProtocolClient] = {}
active_demo = True
demo_step = 0
server_status_lock = threading.Lock()

# --- Server Configuration ---
TOTAL_SERVERS = 5
MACHINE_1_NODES = ["1", "2"]
MACHINE_2_NODES = ["3", "4", "5"]
BASE_CLIENT_PORT = 50050
BASE_RAFT_PORT = 50060

# --- Helper Functions (Adapted from original demo) ---

def clear_data_directory():
    """Clear the data directory for locally managed nodes."""
    nodes_on_this_machine = (
        MACHINE_1_NODES
        if args.machine_id == 1
        else MACHINE_2_NODES
    )
    cleared = False
    for node_id in nodes_on_this_machine:
        data_dir = f"./data/node_{node_id}"
        if os.path.exists(data_dir):
            shutil.rmtree(data_dir)
            cleared = True
        os.makedirs(data_dir, exist_ok=True)
    if cleared:
        logging.info("Cleared local data directories")

def get_server_config(node_id: str, local_ip: str, peer_ip: str) -> Tuple[str, int, int]:
    """Gets the host, client port, and raft port for a given node ID."""
    if node_id in MACHINE_1_NODES:
        host = local_ip if args.machine_id == 1 else peer_ip
    elif node_id in MACHINE_2_NODES:
        host = local_ip if args.machine_id == 2 else peer_ip
    else:
        raise ValueError(f"Unknown node_id: {node_id}")

    client_port = BASE_CLIENT_PORT + int(node_id)
    raft_port = BASE_RAFT_PORT + int(node_id)
    return host, client_port, raft_port

def start_server(
    node_id: str,
    host: str,
    port: int,
    raft_port: int,
    leader_raft_info: Optional[List[Tuple[str, int]]] = None,
):
    """Start a chat server node locally."""
    global local_servers
    data_dir = f"./data/node_{node_id}"
    os.makedirs(data_dir, exist_ok=True) # Ensure data dir exists

    cmd = [
        "python",
        "chat_server.py",
        "--node-id", node_id,
        "--host", "0.0.0.0", # Bind to all interfaces
        "--port", str(port),
        "--raft-port", str(raft_port)
    ]

    if leader_raft_info:
        # Pass leader info as JSON string for joining
        leader_info_json = json.dumps([[h, p] for h, p in leader_raft_info])
        cmd.extend(["--leader-info", leader_info_json])

    logging.info(
        f"Starting server node {node_id} locally, binding to 0.0.0.0:{port} (Raft: {raft_port})"
    )

    # Start the server process
    # Redirect output to /dev/null or a file if it's too noisy for the demo UI
    process = subprocess.Popen(
        cmd,
        # stdout=subprocess.DEVNULL, # Hide server logs from demo console
        # stderr=subprocess.DEVNULL, # Hide server errors from demo console
        universal_newlines=True,
    )

    with server_status_lock:
        local_servers[node_id] = {
            "process": process,
            "host": host, # Publicly reachable host
            "port": port,
            "raft_port": raft_port,
            "status": "starting",
        }

    # Check if process started successfully after a short delay
    time.sleep(3) # Give it a moment to start or fail
    if process.poll() is not None: # Check if process terminated
         with server_status_lock:
            local_servers[node_id]["status"] = "failed_to_start"
         logging.error(f"Server node {node_id} failed to start.")
         return None
    else:
        with server_status_lock:
            local_servers[node_id]["status"] = "online"
        logging.info(f"Server node {node_id} appears to be online.")
        return process


def kill_local_server(node_id: str):
    """Kill a specific server running locally."""
    global local_servers
    if node_id in local_servers:
        logging.info(f"Attempting to kill local server node {node_id}")
        server_info = local_servers[node_id]
        process = server_info["process"]
        try:
            process.terminate()
            process.wait(timeout=3)
            logging.info(f"Terminated server node {node_id}")
        except subprocess.TimeoutExpired:
            logging.warning(
                f"Server node {node_id} did not terminate gracefully, killing..."
            )
            process.kill()
            process.wait() # Ensure kill completes
            logging.info(f"Killed server node {node_id}")
        except Exception as e:
             logging.error(f"Error killing server {node_id}: {e}")

        with server_status_lock:
            local_servers[node_id]["status"] = "offline"
            # Keep the entry in local_servers to show its offline status
            # Optionally remove if you don't want to show killed servers:
            # del local_servers[node_id]
    else:
        logging.warning(
            f"Server node {node_id} not found running locally or already stopped."
        )

def cleanup():
    """Clean up locally running servers and clients."""
    logging.info("Cleaning up local resources...")
    # Stop servers started by this script instance
    with server_status_lock:
        local_node_ids = list(local_servers.keys()) # Get IDs before iterating

    for node_id in local_node_ids:
        if local_servers[node_id]["status"] != "offline":
             kill_local_server(node_id) # Use the function to update status

    # Close clients
    for client_id in list(clients.keys()):
        try:
            clients[client_id].close()
            logging.info(f"Closed client {client_id}")
        except Exception as e:
            logging.error(f"Error closing client {client_id}: {e}")

    # Remove cluster config files if they were created locally
    for i in range(1, TOTAL_SERVERS + 1):
        if os.path.exists(f"cluster_config_{i}.json"):
            os.remove(f"cluster_config_{i}.json")

    logging.info("Local cleanup finished.")

# --- Client and Demo Steps (Mostly unchanged, use console.print) ---

def on_new_message(message):
    """Callback for new message events."""
    console.print(
        f"\n[bold green][PUSH EVENT][/] New message from {message['from_']}: {message['content']}"
    )

def on_delete_message(message):
    """Callback for delete message events."""
    console.print(
        f"\n[bold red][PUSH EVENT][/] Messages deleted: {message['message_ids']}"
    )

def create_client(client_id: str, target_host: str, target_port: int):
    """Create a chat client connected to a specific server."""
    global clients
    try:
        client = CustomProtocolClient(
            target_host,
            target_port,
            on_msg_callback=on_new_message,
            on_delete_callback=on_delete_message,
        )
        clients[client_id] = client
        logging.info(
            f"Created client {client_id} connected to {target_host}:{target_port}"
        )
        return client
    except Exception as e:
        logging.error(f"Failed to create client {client_id}: {e}")
        console.print(f"[bold red]Error:[/bold red] Failed to connect client {client_id} to {target_host}:{target_port}. Check server status and network.")
        return None

# --- Demo Workload Functions (Using console.print) ---

def demo_check_account_exists(client: CustomProtocolClient):
    """Check if an account exists."""
    console.print("\n[bold cyan]----- CHECKING USER ACCOUNTS -----[/]")
    if not client:
        console.print("[yellow]Client not available, skipping step.[/]")
        return False
    try:
        alice_exists = client.account_exists("alice")
        bob_exists = client.account_exists("bob")
        console.print(f"User 'alice' exists: {alice_exists}")
        console.print(f"User 'bob' exists: {bob_exists}")
        return True
    except Exception as e:
        console.print(f"[bold red]Error during username checking:[/bold red] {e}")
        return False

def demo_create_accounts(client: CustomProtocolClient):
    """Demo creating user accounts."""
    console.print("\n[bold cyan]----- CREATING USER ACCOUNTS -----[/]")
    if not client:
        console.print("[yellow]Client not available, skipping step.[/]")
        return False
    try:
        if not client.account_exists("alice"):
            client.create_account("alice", "password")
            console.print("Created account for 'alice'")
        else:
            console.print("Account 'alice' already exists.")

        if not client.account_exists("bob"):
            client.create_account("bob", "password")
            console.print("Created account for 'bob'")
        else:
            console.print("Account 'bob' already exists.")
        return True
    except Exception as e:
        console.print(f"[bold red]Error during account creation:[/bold red] {e}")
        return False

def demo_send_and_read_messages(client1: CustomProtocolClient, client2: CustomProtocolClient):
    """Demo sending and reading messages."""
    console.print("\n[bold cyan]----- SENDING & READING MESSAGES -----[/]")
    if not client1 or not client2:
        console.print("[yellow]One or both clients not available, skipping step.[/]")
        return False

    success = True
    try:
        # Ensure logged in (add login calls if client doesn't persist session)
        try:
            client1.login("alice", "password")
            console.print("Logged in as 'alice' on client1")
        except Exception as e:
             console.print(f"[yellow]Alice login failed (may already be logged in or account issue): {e}[/]")

        try:
            client2.login("bob", "password")
            console.print("Logged in as 'bob' on client2")
        except Exception as e:
             console.print(f"[yellow]Bob login failed (may already be logged in or account issue): {e}[/]")


        # Alice sends to Bob
        msg_id1 = client1.send_message("bob", "Hello Bob from the distributed demo!")
        console.print(f"Alice sent message (ID: {msg_id1})")
        time.sleep(0.5)

        # Bob sends to Alice
        msg_id2 = client2.send_message("alice", "Hi Alice! Distributed setup looks cool.")
        console.print(f"Bob sent message (ID: {msg_id2})")
        time.sleep(0.5)

        # Read messages
        console.print("\n[bold]Bob's messages:[/]")
        messages_bob = client2.read_messages()
        if not messages_bob: console.print("(No messages received yet)")
        for msg in messages_bob:
            ts = datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M:%S')
            console.print(f"  [{ts}] {msg['from_']}: {msg['content']}")

        console.print("\n[bold]Alice's messages:[/]")
        messages_alice = client1.read_messages()
        if not messages_alice: console.print("(No messages received yet)")
        for msg in messages_alice:
            ts = datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M:%S')
            console.print(f"  [{ts}] {msg['from_']}: {msg['content']}")

    except Exception as e:
        console.print(f"[bold red]Error during message send/read:[/bold red] {e}")
        success = False # Mark as failed

    return success

def run_demo_workload(step_name: str):
    """Runs a sequence of demo steps and reports success."""
    global demo_step
    demo_step += 1
    console.print(f"\n\n[bold magenta]=== WORKLOAD {demo_step}: {step_name} ===")
    # Use existing clients, assuming they are connected
    client1 = clients.get("client1")
    client2 = clients.get("client2") # Assumes client2 exists

    if not client1 or not client2:
         console.print("[bold red]Cannot run workload: Clients not initialized properly.[/]")
         return False

    # Attempt to reconnect or verify connection if necessary
    # (Simple approach: rely on initial connection)

    results = []
    results.append(demo_check_account_exists(client1))
    # results.append(demo_create_accounts(client1)) # Create accounts if needed
    time.sleep(2) # Allow replication
    # results.append(demo_send_and_read_messages(client1, client2))

    if all(results):
        console.print(f"[bold green]=== WORKLOAD {demo_step} COMPLETED SUCCESSFULLY ===[/]")
        return True
    else:
        console.print(f"[bold red]=== WORKLOAD {demo_step} FAILED ===[/]")
        return False

# --- UI and Interaction ---

def generate_status_table() -> Table:
    """Generates the Rich table for server status."""
    table = Table(title="Local Server Status")
    table.add_column("Node ID", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Address (Client / Raft)", style="magenta")

    with server_status_lock:
        sorted_node_ids = sorted(local_servers.keys(), key=int)
        for node_id in sorted_node_ids:
            server_info = local_servers[node_id]
            status = server_info["status"]
            if status == "online":
                status_text = "[bold green]● Online[/]"
            elif status == "offline":
                status_text = "[bold red]○ Offline[/]"
            elif status == "starting":
                status_text = "[yellow]◌ Starting...[/]"
            elif status == "failed_to_start":
                 status_text = "[bold red]✗ Failed[/]"
            else:
                status_text = f"[grey]{status}[/]"

            address = f"{server_info['host']}:{server_info['port']} / {server_info['raft_port']}"
            table.add_row(node_id, status_text, address)
    return table

def status_display_thread(live: Live):
    """Thread function to update the status display."""
    while active_demo:
        live.update(generate_status_table())
        time.sleep(2) # Update interval

def user_input_thread(fail_leader_allowed: bool):
    """Thread function to handle user commands for failing nodes."""
    global active_demo
    time.sleep(1) # Let the main thread print initial instructions
    while active_demo:
        try:
            # Use Rich's Prompt for better input handling if needed,
            # but raw input is simpler for just this command.
            cmd = input("\nEnter command ('fail <node_id>' or 'exit'): ").strip().lower()

            if cmd == "exit":
                console.print("[yellow]Exit command received. Shutting down...[/]")
                active_demo = False
                break
            elif cmd.startswith("fail "):
                parts = cmd.split()
                if len(parts) == 2 and parts[1].isdigit():
                    node_id_to_fail = parts[1]

                    if node_id_to_fail == "1" and not fail_leader_allowed:
                         console.print("[bold yellow]Warning:[/bold yellow] Initial leader failure (node 1) is disabled by default for this phase. Use '--fail-leader' if intended.")
                         continue

                    if node_id_to_fail in local_servers:
                        console.print(f"[yellow]Simulating failure for local node {node_id_to_fail}...[/]")
                        kill_local_server(node_id_to_fail)
                    else:
                        console.print(f"[red]Node {node_id_to_fail} is not running locally on this machine.[/]")
                else:
                    console.print("[red]Invalid 'fail' command. Use 'fail <node_id>' (e.g., 'fail 2').[/]")
            elif cmd: # Non-empty command that wasn't recognized
                 console.print(f"[red]Unknown command: '{cmd}'. Available: 'fail <node_id>', 'exit'.[/]")

        except EOFError: # Handle Ctrl+D
             console.print("\n[yellow]EOF detected. Exiting...[/]")
             active_demo = False
             break
        except KeyboardInterrupt: # Handle Ctrl+C in input prompt
             console.print("\n[yellow]Ctrl+C detected. Exiting...[/]")
             active_demo = False
             break
        except Exception as e:
             logging.error(f"Error in input thread: {e}")
             # Avoid crashing the demo due to input errors
             console.print(f"[red]An error occurred processing input: {e}[/]")


# --- Main Demo Logic ---

def run_distributed_demo(args):
    """Run the complete distributed demo."""
    global active_demo, clients

    console.print(f"[bold blue]=== DISTRIBUTED CHAT DEMO (Machine {args.machine_id}) ===[/]")

    local_ip = get_local_ip()
    console.print(f"Local IP detected: [cyan]{local_ip}[/]")

    # Get Peer IP
    peer_ip = args.peer_ip
    if not peer_ip:
        if args.machine_id == 1:
            peer_ip = Prompt.ask("[yellow]Enter the IP address of Machine 2[/]")
        else:
            peer_ip = Prompt.ask("[yellow]Enter the IP address of Machine 1 (Leader)[/]")
    console.print(f"Peer IP configured: [cyan]{peer_ip}[/]")

    # Determine which nodes run locally
    local_node_ids = MACHINE_1_NODES if args.machine_id == 1 else MACHINE_2_NODES
    console.print(f"This machine will run nodes: [cyan]{', '.join(local_node_ids)}[/]")

    # --- Phase 0: Cleanup and Setup ---
    if not args.skip_clear:
        clear_data_directory()

    # --- Phase 1: Start Local Servers ---
    console.print("\n[bold blue]--- Phase 1: Starting Local Servers ---[/]")
    leader_host, _, leader_raft_port = get_server_config("1", local_ip, peer_ip)
    leader_raft_info = [(leader_host, leader_raft_port)] # Raft address of node 1

    for node_id in local_node_ids:
        host, client_port, raft_port = get_server_config(node_id, local_ip, peer_ip)
        is_initial_leader = (node_id == "1")

        start_server(
            node_id,
            host,
            client_port,
            raft_port,
            leader_raft_info=None if is_initial_leader else leader_raft_info,
        )
        # Add a small delay between starting followers to avoid overwhelming the leader
        if not is_initial_leader:
            time.sleep(1)

    console.print("[green]Waiting for cluster to stabilize...[/]")
    time.sleep(10) # Increased wait time for distributed setup

    # --- Phase 2: Start UI and Clients ---
    console.print("\n[bold blue]--- Phase 2: Initializing UI and Clients ---[/]")
    live_display = Live(generate_status_table(), console=console, refresh_per_second=0.5, auto_refresh=False)

    # Start threads
    status_thread = threading.Thread(target=status_display_thread, args=(live_display,), daemon=True)
    input_th = threading.Thread(target=user_input_thread, args=(args.fail_leader,), daemon=True)

    with live_display: # Manage the live display context
        status_thread.start()

        # Create clients - connect both to the initial leader (Node 1)
        leader_client_host, leader_client_port, _ = get_server_config("1", local_ip, peer_ip)
        console.print(f"Connecting clients to initial leader at {leader_client_host}:{leader_client_port}")
        client1 = create_client("client1", leader_client_host, leader_client_port)
        client2 = create_client("client2", leader_client_host, leader_client_port) # Both connect to leader initially

        if not client1 or not client2:
            console.print("[bold red]Failed to create clients. Aborting demo.[/]")
            active_demo = False # Signal threads to stop
            # No need to start input thread if clients failed
        else:
             # Start input thread only if clients are okay
            input_th.start()

            # --- Phase 3: Initial Workload (All Nodes Up) ---
            console.print("\n[bold blue]--- Phase 3: Running Initial Workload (All Nodes Up) ---[/]")
            run_demo_workload("Initial State (5/5 Nodes)")
            time.sleep(2)

            # --- Phase 4: First Failure Simulation (f=1) ---
            console.print("\n[bold blue]--- Phase 4: Simulating First Failure (f=1) ---[/]")
            console.print("[bold yellow]INSTRUCTION:[/bold yellow] Use the 'fail <node_id>' command below.")
            console.print(" - Machine 1 should fail node [cyan]2[/].")
            console.print(" - Machine 2 should fail one of its nodes (e.g., [cyan]3[/]).")
            console.print("[bold]Press Enter here after failures are triggered on BOTH machines.[/bold]")
            try:
                input() # Wait for user confirmation
            except (KeyboardInterrupt, EOFError):
                 active_demo = False # Allow exit here

            if active_demo:
                console.print("\n[bold blue]Running Workload After First Failure (Expected: Success, 3/5 Nodes Active)[/]")
                run_demo_workload("After 1st Failure (3/5 Nodes)")
                time.sleep(2)

            # --- Phase 5: Second Failure Simulation (f=2) ---
            if active_demo:
                console.print("\n[bold blue]--- Phase 5: Simulating Second Failure (f=2) ---[/]")
                console.print("[bold yellow]INSTRUCTION:[/bold yellow] Use the 'fail <node_id>' command below.")
                console.print(" - Machine 2 should fail another one of its nodes (e.g., [cyan]4[/]).")
                console.print("   (Total failed: Node 2, Node 3, Node 4)")
                console.print("[bold]Press Enter here after the second failure is triggered on Machine 2.[/bold]")
                try:
                    input() # Wait for user confirmation
                except (KeyboardInterrupt, EOFError):
                    active_demo = False # Allow exit here

            if active_demo:
                 console.print("\n[bold blue]Running Workload After Second Failure (Expected: Success, 2/5 Nodes Active)[/]")
                 # This tests the boundary of 2f+1 = 5 -> f=2 tolerance
                 run_demo_workload("After 2nd Failure (3/5 Nodes)") # Still 3 nodes active
                 time.sleep(2)

            # --- Phase 6: Third Failure Simulation (f=3) ---
            if active_demo:
                console.print("\n[bold blue]--- Phase 6: Simulating Third Failure (f=3) ---[/]")
                console.print("[bold yellow]INSTRUCTION:[/bold yellow] Use the 'fail <node_id>' command below.")
                console.print(" - Machine 2 should fail its last node ([cyan]5[/]).")
                console.print("   (Total failed: Node 2, Node 3, Node 4, Node 5. Only Node 1 remains).")
                console.print("[bold]Press Enter here after the third failure is triggered on Machine 2.[/bold]")
                try:
                    input() # Wait for user confirmation
                except (KeyboardInterrupt, EOFError):
                    active_demo = False # Allow exit here

            if active_demo:
                console.print("\n[bold blue]Running Workload After Third Failure (Expected: Failure, < Quorum)[/]")
                # Now only 2 nodes are active (1 on M1, 0 on M2, assuming 2,3,4 failed)
                # OR only 1 node is active (1 on M1, if 2,3,4,5 failed)
                # Quorum is ceil((N+1)/2) = ceil(6/2) = 3. We need 3 nodes.
                # With only 1 or 2 nodes left, operations requiring consensus should fail.
                if not run_demo_workload("After 3rd Failure (< Quorum)"):
                     console.print("[bold green]Workload failed as expected due to lack of quorum.[/]")
                else:
                     console.print("[bold red]Workload unexpectedly succeeded. Quorum logic might differ or client connected to non-leader performing reads?[/]")
                time.sleep(2)


        # --- Demo End ---
        if active_demo: # If not already exiting
            console.print("\n[bold green]=== DISTRIBUTED DEMO COMPLETED ===[/]")
            console.print("Enter 'exit' or press Ctrl+C to clean up.")

        # Keep running until 'exit' or Ctrl+C in the input thread
        while active_demo:
            time.sleep(0.5)

        # Wait for threads to finish (input thread sets active_demo=False)
        console.print("Waiting for threads to stop...")
        if input_th.is_alive():
            input_th.join(timeout=2)

        # Status thread is daemon, will exit automatically, but ensure live display stops
        if 'live_display' in locals() and live_display.is_started:
            live_display.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Distributed Chat System Demo")
    parser.add_argument(
        "--machine-id",
        type=int,
        choices=[1, 2],
        required=True,
        help="ID of the machine this script is running on (1 or 2).",
    )
    parser.add_argument(
        "--peer-ip",
        type=str,
        default=None,
        help="IP address of the other machine. If not provided, will prompt.",
    )
    parser.add_argument(
        "--skip-clear",
        action="store_true",
        help="Skip clearing local data directories.",
    )
    parser.add_argument(
        "--fail-leader",
        action="store_true",
        help="Allow failing the initial leader (node 1) via the 'fail' command.",
    )
    args = parser.parse_args()

    try:
        run_distributed_demo(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo interrupted by user (Ctrl+C in main thread).[/]")
        active_demo = False # Signal threads
    except Exception as e:
        console.print(f"\n[bold red]Demo failed with unexpected error:[/bold red] {e}")
        logging.exception("Unhandled exception in main demo.") # Log traceback
        active_demo = False # Signal threads
    finally:
        cleanup()
        console.print("[bold blue]Cleanup complete. Exiting.[/]")
