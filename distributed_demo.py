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
# Removed Live, Layout, Panel, Text

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
            s.connect(("10.255.255.255", 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = "127.0.0.1"
        finally:
            s.close()
        return IP

# Configure logging (basic for demo, server logs go direct to stdout/err)
logging.basicConfig(
    level=logging.INFO,
    format="[DEMO %(levelname)s] %(message)s",
)

# --- Global Variables ---
console = Console()
all_servers_status: Dict[str, Dict[str, Any]] = {} # ALL servers (local & remote)
local_servers_procs: Dict[str, subprocess.Popen] = {} # Local processes only
clients: Dict[str, CustomProtocolClient] = {}
active_demo = True
status_lock = threading.Lock() # Lock for accessing all_servers_status

# --- Server Configuration ---
TOTAL_SERVERS = 5
MACHINE_1_NODES = ["1", "2"]
MACHINE_2_NODES = ["3", "4", "5"]
INITIAL_LEADER_ID = str(2)
BASE_CLIENT_PORT = 50050
BASE_RAFT_PORT = 50060

# --- Helper Functions ---

def clear_data_directory(local_node_ids: List[str]):
    """Clear the data directory for locally managed nodes."""
    cleared = False
    for node_id in local_node_ids:
        data_dir = f"./data/node_{node_id}"
        if os.path.exists(data_dir):
            try:
                shutil.rmtree(data_dir)
                cleared = True
            except OSError as e:
                 logging.error(f"Error removing directory {data_dir}: {e}")
        try:
            os.makedirs(data_dir, exist_ok=True)
        except OSError as e:
            logging.error(f"Error creating directory {data_dir}: {e}")
    if cleared:
        logging.info("Cleared local data directories")

def get_server_config(node_id: str, local_ip: str, peer_ip: str, machine_id: int) -> Tuple[str, int, int]:
    """Gets the host, client port, and raft port for a given node ID."""
    if node_id in MACHINE_1_NODES:
        host = local_ip if machine_id == 1 else peer_ip
    elif node_id in MACHINE_2_NODES:
        host = local_ip if machine_id == 2 else peer_ip
    else:
        raise ValueError(f"Unknown node_id: {node_id}")

    client_port = BASE_CLIENT_PORT + int(node_id)
    raft_port = BASE_RAFT_PORT + int(node_id)
    return host, client_port, raft_port

def start_server(
    node_id: str,
    host: str, # Publicly reachable host
    port: int,
    raft_port: int,
    leader_raft_info: Optional[List[Tuple[str, int]]] = None,
):
    """Start a chat server node locally, letting output go to terminal."""
    global all_servers_status, local_servers_procs

    data_dir = f"./data/node_{node_id}"
    try:
        os.makedirs(data_dir, exist_ok=True) # Ensure data dir exists
    except OSError as e:
        logging.error(f"Failed to create data directory {data_dir}: {e}")
        with status_lock:
            all_servers_status[node_id]["status"] = "failed_to_start"
            all_servers_status[node_id]["details"] = "Dir creation error"
        return None

    cmd = [
        "python", # Use the python in the current env
        "chat_server.py",
        "--node-id", node_id,
        "--host", "0.0.0.0", # Bind to all interfaces locally
        "--port", str(port),
        "--raft-port", str(raft_port)
    ]

    if leader_raft_info:
        leader_info_json = json.dumps([[h, p] for h, p in leader_raft_info])
        cmd.extend(["--leader-info", leader_info_json])

    logging.info(
        f"Starting server node {node_id} locally (Raft: {raft_port}). Output will appear below."
    )
    with status_lock:
        all_servers_status[node_id]["status"] = "starting"
        all_servers_status[node_id]["details"] = ""

    try:
        # Let subprocess inherit stdout/stderr - logs will print directly
        process = subprocess.Popen(cmd)
        local_servers_procs[node_id] = process

    except Exception as e:
        logging.error(f"Failed to launch server process for node {node_id}: {e}")
        with status_lock:
            all_servers_status[node_id]["status"] = "failed_to_start"
            all_servers_status[node_id]["details"] = f"Launch error: {e}"
        return None

    # Check status after a delay (non-blocking)
    threading.Timer(1.5, check_server_started, args=[node_id, process]).start()
    return process

def check_server_started(node_id: str, process: subprocess.Popen):
    """Callback to check if a server started successfully."""
    global all_servers_status
    # Check if process is still running
    if process.poll() is None:
        with status_lock:
            # Only update if still 'starting', might have been killed
            if all_servers_status.get(node_id, {}).get("status") == "starting":
                all_servers_status[node_id]["status"] = "online"
        logging.info(f"Server node {node_id} appears to be online.")
    else: # Process terminated
        with status_lock:
            # Only update if still 'starting'
            if all_servers_status.get(node_id, {}).get("status") == "starting":
                all_servers_status[node_id]["status"] = "failed_to_start"
                all_servers_status[node_id]["details"] = f"Exited code {process.returncode}"
        logging.error(f"Server node {node_id} failed to start (exit code: {process.returncode}).")


def kill_local_server(node_id: str):
    """Kill a specific server running locally."""
    global all_servers_status, local_servers_procs
    if node_id in local_servers_procs:
        logging.info(f"Attempting to kill local server node {node_id}")
        process = local_servers_procs[node_id]
        status_before_kill = "unknown"
        with status_lock:
             status_before_kill = all_servers_status.get(node_id, {}).get("status", "unknown")

        if status_before_kill not in ["offline", "killed", "failed_to_start", "error_killing"]:
            try:
                process.terminate()
                try:
                    process.wait(timeout=2)
                    logging.info(f"Terminated server node {node_id}")
                    exit_code = process.returncode
                except subprocess.TimeoutExpired:
                    logging.warning(
                        f"Server node {node_id} did not terminate gracefully, sending SIGKILL..."
                    )
                    process.kill()
                    process.wait() # Ensure kill completes
                    logging.info(f"Killed server node {node_id}")
                    exit_code = "killed"

                with status_lock:
                    all_servers_status[node_id]["status"] = "offline"
                    all_servers_status[node_id]["details"] = f"Exit code {exit_code}"
                del local_servers_procs[node_id]

            except Exception as e:
                logging.error(f"Error killing server {node_id}: {e}")
                with status_lock:
                    all_servers_status[node_id]["status"] = "error_killing"
                    all_servers_status[node_id]["details"] = str(e)
                if node_id in local_servers_procs:
                     del local_servers_procs[node_id]
        else:
             logging.info(f"Server node {node_id} was already {status_before_kill}.")
             if node_id in local_servers_procs:
                 del local_servers_procs[node_id] # Cleanup proc entry if needed

    else:
        logging.warning(
            f"Server node {node_id} not found running locally or already stopped."
        )

def cleanup():
    """Clean up locally running servers and clients."""
    global active_demo
    active_demo = False # Signal threads/loops to stop
    logging.info("Cleaning up local resources...")

    # Stop servers started by this script instance
    local_node_ids = list(local_servers_procs.keys()) # Get IDs before iterating
    for node_id in local_node_ids:
        kill_local_server(node_id) # Use the function to update status and remove proc

    # Close clients
    for client_id in list(clients.keys()):
        try:
            clients[client_id].close()
            logging.info(f"Closed client {client_id}")
        except Exception as e:
            logging.error(f"Error closing client {client_id}: {e}")

    logging.info("Local cleanup finished.")

# --- Client Callbacks ---

def on_new_message(message):
    """Callback for new message events."""
    # Print directly, will interleave with server logs and input prompt
    console.print(
        f"\n[bold green][PUSH][/] New msg from {message['from_']}: {message['content']}"
    )

def on_delete_message(message):
    """Callback for delete message events."""
    console.print(
        f"\n[bold red][PUSH][/] Msgs deleted: {message['message_ids']}"
    )

# --- Client Creation ---

def create_client(client_id: str, target_node_id: str):
    """Create a chat client connected to a specific server node ID."""
    global clients, all_servers_status
    if target_node_id not in all_servers_status:
        logging.error(f"Cannot create client {client_id}: Target node {target_node_id} not in config.")
        return None

    target_info = all_servers_status[target_node_id]
    target_host = target_info["host"]
    target_port = target_info["port"]

    try:
        client = CustomProtocolClient(
            target_host,
            target_port,
            on_msg_callback=on_new_message,
            on_delete_callback=on_delete_message,
        )
        clients[client_id] = client
        logging.info(
            f"Created client {client_id} connected to Node {target_node_id} ({target_host}:{target_port})"
        )
        return client
    except Exception as e:
        logging.error(f"Failed to create client {client_id} to Node {target_node_id}: {e}")
        console.print(f"[bold red]Error:[/bold red] Failed to connect client {client_id} to Node {target_node_id} ({target_host}:{target_port}).")
        return None

# --- Demo Workload Function ---

def run_demo_workload(step_name: str):
    """Runs a sequence of demo steps and reports success."""
    console.print(f"\n[bold magenta]=== Running Workload: {step_name} ===")
    client1 = clients.get("client1")

    if not client1:
         console.print("[bold red]Cannot run workload: Client 'client1' not available.[/]")
         return False

    # --- Define workload steps ---
    def step_check_accounts(c):
        console.print("[cyan]-- Checking accounts 'alice', 'bob'...[/]")
        try:
            _ = c.account_exists("alice")
            _ = c.account_exists("bob")
            console.print("[green]Account check successful (server reachable).[/]")
            return True
        except Exception as e:
            console.print(f"[red]Account check failed: {e}[/]")
            return False

    def step_create_accounts(c):
        console.print("[cyan]-- Creating accounts 'alice', 'bob' (if needed)...[/]")
        try:
            res_a, msg_a = c.create_account("alice", "password")
            if res_a or "exists" in msg_a:
                 console.print(f"Alice account: {msg_a}")
            else:
                 console.print(f"[red]Failed creating alice: {msg_a}[/]")
                 return False

            res_b, msg_b = c.create_account("bob", "password")
            if res_b or "exists" in msg_b:
                 console.print(f"Bob account: {msg_b}")
            else:
                 console.print(f"[red]Failed creating bob: {msg_b}[/]")
                 return False

            console.print("[green]Account creation step successful.[/]")
            return True
        except Exception as e:
            console.print(f"[red]Account creation failed: {e}[/]")
            return False

    def step_send_message(c):
        console.print("[cyan]-- Alice sending message to Bob...[/]")
        try:
            login_ok, login_msg, _ = c.login("alice", "password")
            if not login_ok:
                console.print(f"[red]Login failed for alice: {login_msg}[/]")
                if "No such user" in login_msg:
                    c.create_account("alice", "password")
                    login_ok, login_msg, _ = c.login("alice", "password")
                    if not login_ok:
                         console.print(f"[red]Login still failed after create: {login_msg}[/]")
                         return False
                else:
                    return False

            if not c.account_exists("bob"):
                 c.create_account("bob", "password")

            content = f"Hello from Alice @ {datetime.now().isoformat()}"
            sent, msg, _ = c.send_message("bob", content)
            if sent:
                console.print(f"[green]Message sent: {msg}[/]")
                return True
            else:
                console.print(f"[red]Message send failed: {msg}[/]")
                return False
        except Exception as e:
            console.print(f"[red]Send message failed: {e}[/]")
            return False

    # --- Execute workload steps ---
    results = []
    results.append(step_check_accounts(client1))
    time.sleep(1) # Allow replication

    if all(results):
        console.print(f"[bold green]=== WORKLOAD '{step_name}' COMPLETED SUCCESSFULLY ===[/]")
        return True
    else:
        console.print(f"[bold red]=== WORKLOAD '{step_name}' FAILED ===[/]")
        return False

# --- Status Table Generation ---

def generate_status_table() -> Table:
    """Generates the Rich table for server status."""
    global all_servers_status
    table = Table(title="", expand=True)
    table.add_column("Node ID", style="cyan", no_wrap=True)
    table.add_column("Location", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Address (Client / Raft)", style="magenta")

    with status_lock:
        sorted_node_ids = sorted(all_servers_status.keys(), key=int)
        for node_id in sorted_node_ids:
            server_info = all_servers_status[node_id]
            status = server_info.get("status", "unknown")
            location = server_info.get("location", "Unknown")

            if status == "online":
                status_text = "[bold green]● Online[/]"
            elif status == "offline":
                status_text = "[bold red]○ Offline[/]"
            elif status == "starting":
                status_text = "[yellow]◌ Starting...[/]"
            elif status == "failed_to_start":
                 status_text = "[bold red]✗ Failed[/]"
            elif status == "error_killing":
                 status_text = "[bold red]⚠ Error Kill[/]"
            elif status == "killed":
                 status_text = "[bold red]○ Killed[/]"
            else: # unknown or other
                status_text = f"[grey]{status}[/]"

            if location == "local":
                 loc_text = "[blue]Local[/]"
            elif location == "remote":
                 loc_text = "[purple]Remote[/]"
            else:
                 loc_text = "[dim]?[/]"

            address = f"{server_info.get('host', '?')}:{server_info.get('port', '?')} / {server_info.get('raft_port', '?')}"
            table.add_row(node_id, loc_text, status_text, address)
    return table

# --- Main Demo Logic ---

def run_simple_interactive_demo(args):
    """Run the simplified interactive distributed demo."""
    global active_demo, clients, all_servers_status

    console.print(f"[bold blue]=== SIMPLE INTERACTIVE DISTRIBUTED CHAT DEMO (Machine {args.machine_id}) ===[/]")

    local_ip = get_local_ip()
    console.print(f"Local IP detected: [cyan]{local_ip}[/]")

    # Get Peer IP
    peer_ip = args.peer_ip
    if not peer_ip:
        if local_ip.startswith("192.168.") or local_ip.startswith("10."):
             peer_ip = local_ip
             console.print(f"[yellow]Peer IP not provided, assuming local testing (peer={local_ip})[/]")
        else:
            if args.machine_id == 1:
                peer_ip = console.input("[yellow]Enter the IP address of Machine 2[/]: ")
            else:
                peer_ip = console.input("[yellow]Enter the IP address of Machine 1 (Leader)[/]: ")
    console.print(f"Peer IP configured: [cyan]{peer_ip}[/]")

    local_node_ids = MACHINE_1_NODES if args.machine_id == 1 else MACHINE_2_NODES
    console.print(f"This machine will run nodes: [cyan]{', '.join(local_node_ids)}[/]")

    # --- Phase 0: Cleanup and Setup ---
    if not args.skip_clear:
        clear_data_directory(local_node_ids)

    # Initialize status for all nodes
    with status_lock:
        for i in range(1, TOTAL_SERVERS + 1):
            node_id = str(i)
            host, client_port, raft_port = get_server_config(node_id, local_ip, peer_ip, args.machine_id)
            all_servers_status[node_id] = {
                "host": host,
                "port": client_port,
                "raft_port": raft_port,
                "location": "local" if node_id in local_node_ids else "remote",
                "status": "pending",
                "details": ""
            }

    # --- Phase 1: Start Local Servers ---
    console.print("\n[bold blue]--- Starting Local Servers ---[/]")
    leader_host, _, leader_raft_port = get_server_config(INITIAL_LEADER_ID, local_ip, peer_ip, args.machine_id)
    leader_raft_info = [(leader_host, leader_raft_port)]

    for node_id in local_node_ids:
        server_info = all_servers_status[node_id]
        is_initial_leader = (node_id == INITIAL_LEADER_ID)
        start_server(
            node_id,
            server_info["host"],
            server_info["port"],
            server_info["raft_port"],
            leader_raft_info=None if is_initial_leader else leader_raft_info,
        )
        if not is_initial_leader: time.sleep(0.5)

    console.print("[green]Waiting for servers to initialize...[/]")
    time.sleep(5)

    # --- Phase 2: Create Client ---
    console.print("\n[bold blue]--- Initializing Client ---[/]")
    console.print(f"Connecting client 'client1' to cluster...")
    client1 = create_client("client1", INITIAL_LEADER_ID)
    if not client1:
        console.print("[bold red]Failed to create client. 'test' command may fail.[/]")

    # --- Phase 3: Interactive Command Loop ---
    console.print("\n[bold blue]--- Interactive Mode ---[/]")
    while active_demo:
        try:
            cmd = console.input("[bold]Enter command ('status', 'test', 'kill <id>', 'start <id>', 'exit'):[/] ").strip().lower()

            if not cmd: # Handle empty input
                continue

            if cmd == "exit":
                console.print("[yellow]Exit command received. Shutting down...[/]")
                active_demo = False
            elif cmd.startswith("kill "):
                parts = cmd.split()
                if len(parts) == 2 and parts[1].isdigit():
                    node_id_to_fail = parts[1]
                    if node_id_to_fail not in all_servers_status:
                         console.print(f"[red]Invalid node ID: {node_id_to_fail}. Valid IDs: {list(all_servers_status.keys())}[/]")
                         continue
                    if node_id_to_fail == INITIAL_LEADER_ID and not args.fail_leader:
                         console.print(f"[bold yellow]Warning:[/bold yellow] Initial leader failure (node {INITIAL_LEADER_ID}) is disabled. Use '--fail-leader' if intended.")
                         continue
                    if node_id_to_fail in local_node_ids:
                        console.print(f"[yellow]Simulating failure for local node {node_id_to_fail}...[/]")
                        kill_local_server(node_id_to_fail)
                    else:
                        console.print(f"[yellow]Node {node_id_to_fail} is remote. Cannot kill directly.[/]")
                else:
                    console.print("[red]Invalid 'kill' command. Use 'kill <node_id>' (e.g., 'fail 2').[/]")
            elif cmd.startswith("start "):
                parts = cmd.split()
                if len(parts) == 2 and parts[1].isdigit():
                    node_id_to_start = parts[1]
                    # 1. Validate Node ID
                    if node_id_to_start not in all_servers_status:
                        console.print(f"[red]Invalid node ID: {node_id_to_start}. Valid IDs: {list(all_servers_status.keys())}[/]")
                        continue

                    # 2. Check if Node is Local
                    if node_id_to_start not in local_node_ids:
                        console.print(f"[yellow]Node {node_id_to_start} is remote. Cannot start locally.[/]")
                        continue

                    # 3. Check if Node is Already Running or Starting
                    with status_lock:
                        current_status = all_servers_status[node_id_to_start].get("status", "unknown")
                    if current_status in ["online", "starting"]:
                        console.print(f"[yellow]Node {node_id_to_start} is already {current_status}.[/]")
                        continue
                    # Safety check: Ensure process isn't lingering in our tracking dict
                    if node_id_to_start in local_servers_procs:
                        console.print(f"[yellow]Node {node_id_to_start} process handle still exists unexpectedly. Check status or try failing again.[/]")
                        continue

                    # 4. Prepare to Start
                    console.print(f"[yellow]Attempting to start local node {node_id_to_start}...[/]")
                    server_info = all_servers_status[node_id_to_start]

                    # 5. Determine Leader Info for Rejoining
                    #    For simplicity, always point restarted nodes to the INITIAL leader's Raft address.
                    #    The Raft protocol should handle finding the current actual leader.
                    leader_info_config = all_servers_status[INITIAL_LEADER_ID]
                    leader_raft_details = [(leader_info_config["host"], leader_info_config["raft_port"])]

                    # 6. Call start_server
                    #    Note: start_server does NOT clear the data directory, allowing potential state recovery.
                    start_server(
                        node_id_to_start,
                        server_info["host"],
                        server_info["port"],
                        server_info["raft_port"],
                        leader_raft_info=leader_raft_details, # Provide leader info to rejoin
                    )
                    # Give it a moment to begin the startup process
                    time.sleep(1.0)

                else:
                    console.print("[red]Invalid 'start' command. Use 'start <node_id>' (e.g., 'start 1').[/]")
            elif cmd == "test":
                 run_demo_workload(f"Manual Test @ {datetime.now().strftime('%H:%M:%S')}")
            elif cmd == "status":
                 console.print(generate_status_table()) # Print the table on demand
            else:
                 console.print(f"[red]Unknown command: '{cmd}'. Available: 'kill <id>', 'start <id>', 'test', 'status', 'exit'.[/]")

        except EOFError:
             console.print("\n[yellow]EOF detected. Exiting...[/]")
             active_demo = False
        except KeyboardInterrupt:
             console.print("\n[yellow]Ctrl+C detected. Exiting...[/]")
             active_demo = False
        except Exception as e:
             logging.error(f"Error processing input: {e}")
             console.print(f"[red]An error occurred processing input: {e}[/]")

    # --- Demo End ---
    console.print("Exiting interactive loop...")
    # Cleanup is handled in the finally block


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Interactive Distributed Chat Demo")
    parser.add_argument(
        "--machine-id", type=int, choices=[1, 2], required=True,
        help="ID of the machine this script is running on (1 or 2).",
    )
    parser.add_argument(
        "--peer-ip", type=str, default=None,
        help="IP address of the other machine. If not provided, will attempt auto-detect or prompt.",
    )
    parser.add_argument(
        "--skip-clear", action="store_true", help="Skip clearing local data directories.",
    )
    parser.add_argument(
        "--fail-leader", action="store_true",
        help="Allow failing the initial leader (node 1) via the 'fail' command.",
    )
    args = parser.parse_args()

    try:
        run_simple_interactive_demo(args)
    except KeyboardInterrupt:
        # This handles Ctrl+C if it happens outside the input prompt
        console.print("\n[yellow]Demo interrupted by user (Ctrl+C in main thread).[/]")
        active_demo = False
    except Exception as e:
        console.print(f"\n[bold red]Demo failed with unexpected error:[/bold red] {e}")
        logging.exception("Unhandled exception in main demo.")
        active_demo = False
    finally:
        cleanup()
        console.print("[bold blue]Cleanup complete. Exiting.[/]")
