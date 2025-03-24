import threading
import logging
import time
import random
import grpc
import asyncio
from concurrent import futures
import json

# Import our modules
import storage
from config import ClusterConfig

# Import the protobuf-generated modules
import raft_pb2
import raft_pb2_grpc

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
)

# Constants
ELECTION_TIMEOUT_MIN = 15000000  # milliseconds
ELECTION_TIMEOUT_MAX = 30000000  # milliseconds
HEARTBEAT_INTERVAL = 100    # milliseconds

# Raft node states
FOLLOWER = "FOLLOWER"
CANDIDATE = "CANDIDATE"
LEADER = "LEADER"

class RaftNode(raft_pb2_grpc.RaftServiceServicer):
    def __init__(self, node_id, config, state_machine, make_leader):
        self.node_id = node_id
        self.config = config
        self.state_machine = state_machine
        
        # Initialize persistent storage
        self.persistent_log = storage.PersistentLog(node_id)
        
        # Initialize volatile state
        self.state = FOLLOWER
        self.current_leader = None
        if make_leader:
            self.state = LEADER
            self.current_leader = node_id
        self.last_heartbeat = time.time()
        self.votes_received = set()
        
        # Initialize leader volatile state
        self.next_index = {}
        self.match_index = {}
        
        # Command queue for client requests
        self.command_queue = asyncio.Queue()
        
        # Locks
        self.state_lock = threading.RLock()
        self.election_timer = None
        
        # gRPC server for Raft communication
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        raft_pb2_grpc.add_RaftServiceServicer_to_server(self, self.server)
        
        # Get node info
        _, node_info = self.config.get_current_node()
        if not node_info:
            raise ValueError(f"Node {node_id} not found in config")
        
        # Start the server
        self.server.add_insecure_port(f"{node_info['host']}:{node_info['raft_port']}")
        self.server.start()
        
        # Initialize all node connections
        self.node_stubs = {}
        for nid, info in self.config.get_nodes().items():
            if nid != self.node_id:
                channel = grpc.insecure_channel(f"{info['host']}:{info['raft_port']}")
                self.node_stubs[nid] = raft_pb2_grpc.RaftServiceStub(channel)
        
        print(f"Raft port: {node_info['raft_port']}")
        # Start background tasks
        self.running = True
        self.election_thread = threading.Thread(target=self._run_election_timer)
        self.election_thread.daemon = True
        self.election_thread.start()
        
        self.append_entries_thread = threading.Thread(target=self._run_append_entries)
        self.append_entries_thread.daemon = True
        self.append_entries_thread.start()
        
        self.apply_command_thread = threading.Thread(target=self._run_apply_command)
        self.apply_command_thread.daemon = True
        self.apply_command_thread.start()
        
        logging.info(f"Raft node {self.node_id} started")
    
    def _run_election_timer(self):
        """Background thread to handle election timeout and start elections."""
        while self.running:
            with self.state_lock:
                # Only check for election timeout if we're not already a leader
                if self.state != LEADER:
                    elapsed = (time.time() - self.last_heartbeat) * 1000  # convert to ms
                    timeout = random.randint(ELECTION_TIMEOUT_MIN, ELECTION_TIMEOUT_MAX)
                    
                    if elapsed >= timeout:
                        self._start_election()
            
            # Sleep a small amount to avoid busy waiting
            time.sleep(0.01)
    
    def _run_append_entries(self):
        """Background thread for leaders to send AppendEntries RPCs."""
        while self.running:
            with self.state_lock:
                if self.state == LEADER:
                    self._send_append_entries()
            
            # Sleep for heartbeat interval
            time.sleep(HEARTBEAT_INTERVAL / 1000)
    
    def _run_apply_command(self):
        """Background thread to apply committed entries to the state machine."""
        while self.running:
            with self.state_lock:
                commit_index = self.persistent_log.get_commit_index()
                last_applied = self.persistent_log.get_last_applied()
                
                if commit_index > last_applied:
                    # Apply commands to state machine
                    for i in range(last_applied + 1, commit_index + 1):
                        entry = self.persistent_log.get_entries(i, i + 1)[0]
                        if "command" in entry:
                            self.state_machine.apply_command(entry["command"], log_index=i)
                    
                    self.persistent_log.set_last_applied(commit_index)
            
            # Sleep a small amount to avoid busy waiting
            time.sleep(0.01)
    
    def _reset_election_timer(self):
        """Reset the election timer."""
        self.last_heartbeat = time.time()
    
    def _start_election(self):
        """Start an election for a new leader."""
        with self.state_lock:
            # Increment current term
            current_term = self.persistent_log.get_current_term() + 1
            self.persistent_log.set_current_term(current_term)
            
            # Transition to candidate state
            self.state = CANDIDATE
            
            # Vote for self
            self.persistent_log.set_voted_for(self.node_id)
            self.votes_received = {self.node_id}
            
            logging.info(f"Starting election for term {current_term}")
            
            # Reset election timer
            self._reset_election_timer()
            
            # Request votes from all other nodes
            last_log_index = self.persistent_log.get_last_log_index()
            last_log_term = self.persistent_log.get_last_log_term()
            
            for node_id, stub in self.node_stubs.items():
                try:
                    request = raft_pb2.RequestVoteRequest(
                        term=current_term,
                        candidate_id=self.node_id,
                        last_log_index=last_log_index,
                        last_log_term=last_log_term
                    )
                    
                    # Send request vote in a separate thread to avoid blocking
                    threading.Thread(
                        target=self._request_vote_thread,
                        args=(node_id, stub, request)
                    ).start()
                except Exception as e:
                    logging.error(f"Error sending RequestVote to {node_id}: {e}")
    
    def _request_vote_thread(self, node_id, stub, request):
        """Thread to send a RequestVote RPC to a node."""
        try:
            response = stub.RequestVote(request)
            
            with self.state_lock:
                # If we're no longer a candidate or term has changed, ignore the response
                if self.state != CANDIDATE or response.term != self.persistent_log.get_current_term():
                    return
                
                # If the response term is higher than our term, become a follower
                if response.term > self.persistent_log.get_current_term():
                    self._become_follower(response.term)
                    return
                
                # If we received a vote, count it
                if response.vote_granted:
                    self.votes_received.add(node_id)
                    
                    # If we have a majority of votes, become the leader
                    if len(self.votes_received) > len(self.config.get_nodes()) / 2:
                        self._become_leader()
        except Exception as e:
            logging.error(f"Error in RequestVote thread for {node_id}: {e}")
    
    def _become_follower(self, term):
        """Transition to follower state."""
        logging.info(f"Becoming follower for term {term}")
        self.state = FOLLOWER
        self.persistent_log.set_current_term(term)
        self.persistent_log.set_voted_for(None)
        self._reset_election_timer()
    
    def _become_leader(self):
        """Transition to leader state."""
        with self.state_lock:
            if self.state != CANDIDATE:
                return
            
            logging.info(f"Becoming leader for term {self.persistent_log.get_current_term()}")
            self.state = LEADER
            self.current_leader = self.node_id
            
            # Initialize leader state
            last_log_index = self.persistent_log.get_last_log_index()
            for node_id in self.config.get_nodes():
                if node_id != self.node_id:
                    self.next_index[node_id] = last_log_index + 1
                    self.match_index[node_id] = 0
            
            # Send initial empty AppendEntries RPCs (heartbeats)
            self._send_append_entries()
    
    def _send_append_entries(self):
        """Send AppendEntries RPCs to all followers."""
        current_term = self.persistent_log.get_current_term()
        
        for node_id, stub in self.node_stubs.items():
            # Prepare entries to send
            next_idx = self.next_index.get(node_id, 0)
            last_log_index = self.persistent_log.get_last_log_index()
            
            # If follower is up to date, just send heartbeat
            if next_idx > last_log_index:
                entries = []
                prev_log_index = last_log_index
                prev_log_term = self.persistent_log.get_last_log_term()
            else:
                # Send at most 100 entries at a time
                entries = self.persistent_log.get_entries(next_idx, next_idx + 100)
                prev_log_index = next_idx - 1
                prev_log_term = 0
                
                if prev_log_index >= 0:
                    prev_log_entry = self.persistent_log.get_entries(prev_log_index, prev_log_index + 1)
                    if prev_log_entry:
                        prev_log_term = prev_log_entry[0]["term"]
            
            # Prepare request
            request = raft_pb2.AppendEntriesRequest(
                term=current_term,
                leader_id=self.node_id,
                prev_log_index=prev_log_index,
                prev_log_term=prev_log_term,
                entries=[json.dumps(entry) for entry in entries],
                leader_commit=self.persistent_log.get_commit_index()
            )
            
            # Send request in a separate thread
            threading.Thread(
                target=self._append_entries_thread,
                args=(node_id, stub, request)
            ).start()
    
    def _append_entries_thread(self, node_id, stub, request):
        """Thread to send an AppendEntries RPC to a node."""
        try:
            response = stub.AppendEntries(request)
            
            with self.state_lock:
                # If we're no longer the leader or term has changed, ignore the response
                if self.state != LEADER or response.term != self.persistent_log.get_current_term():
                    return
                
                # If the response term is higher than our term, become a follower
                if response.term > self.persistent_log.get_current_term():
                    self._become_follower(response.term)
                    return
                
                # If append was successful, update match index and next index
                if response.success:
                    # Calculate the index of the last entry we sent
                    entries = [json.loads(e) for e in request.entries]
                    if entries:
                        self.match_index[node_id] = request.prev_log_index + len(entries)
                        self.next_index[node_id] = self.match_index[node_id] + 1
                    
                    # Update commit index if needed
                    self._check_commit_index()
                else:
                    # If append failed, decrement next index and retry
                    self.next_index[node_id] = max(0, self.next_index[node_id] - 1)
        except Exception as e:
            logging.error(f"Error in AppendEntries thread for {node_id}: {e}")
    
    def _check_commit_index(self):
        """Check if we can advance the commit index."""
        current_term = self.persistent_log.get_current_term()
        commit_index = self.persistent_log.get_commit_index()
        last_log_index = self.persistent_log.get_last_log_index()
        
        # Try to advance commit index
        for n in range(commit_index + 1, last_log_index + 1):
            # Count nodes that have replicated this entry
            count = 1  # Start with 1 for self
            for node_id in self.match_index:
                if self.match_index[node_id] >= n:
                    count += 1
            
            # Check if we have a majority
            if count > len(self.config.get_nodes()) / 2:
                # Only commit if entry is from current term
                entries = self.persistent_log.get_entries(n, n + 1)
                if entries and entries[0]["term"] == current_term:
                    self.persistent_log.set_commit_index(n)
                    logging.debug(f"Advanced commit index to {n}")
    
    def _recover_from_snapshot(self):
        """Recover state by applying logs since the last snapshot."""
        last_snapshot_index = self.state_machine.get_last_snapshot_index()
        commit_index = self.persistent_log.get_commit_index()
        
        # Always replay from snapshot to commit_index
        logging.info(f"Recovering from snapshot at index {last_snapshot_index}")
        
        # Set last_applied to snapshot point initially
        self.persistent_log.set_last_applied(last_snapshot_index)
        
        # Apply logs since the snapshot up to committed index
        for i in range(last_snapshot_index + 1, commit_index + 1):
            entry = self.persistent_log.get_entries(i, i + 1)[0]
            if "command" in entry:
                self.state_machine.apply_command(entry["command"], log_index=i)
        
        # Update last_applied to match what we've actually applied
        self.persistent_log.set_last_applied(commit_index)
        
        logging.info(f"Recovery complete - applied commands from index {last_snapshot_index+1} to {commit_index}")

    async def submit_command(self, command):
        """Submit a command to the Raft cluster."""
        with self.state_lock:
            if self.state != LEADER:
                if self.current_leader:
                    # Redirect to current leader
                    return False, f"Not the leader. Current leader is {self.current_leader}"
                else:
                    return False, "No leader available. Try again later."
            
            # Create a new log entry
            entry = {
                "term": self.persistent_log.get_current_term(),
                "command": command
            }
            
            # Append to local log
            last_index = self.persistent_log.get_last_log_index()
            success, new_last_index = self.persistent_log.append_entries([entry], last_index + 1)
            
            if not success:
                return False, "Failed to append to local log"
            
            # Wait for command to be committed
            future = asyncio.Future()
            self.command_queue.put_nowait((new_last_index, future))
            
            # Send append entries to all followers
            self._send_append_entries()
            
            # Wait for the result with a timeout
            try:
                result = await asyncio.wait_for(future, timeout=5.0)
                return True, result
            except asyncio.TimeoutError:
                return False, "Timeout waiting for command to be committed"
    
    # gRPC service methods
    def RequestVote(self, request, context):
        with self.state_lock:
            current_term = self.persistent_log.get_current_term()
            
            # If the candidate's term is lower than our term, reject vote
            if request.term < current_term:
                return raft_pb2.RequestVoteResponse(term=current_term, vote_granted=False)
            
            # If the candidate's term is higher than our term, update our term
            if request.term > current_term:
                self._become_follower(request.term)
            
            voted_for = self.persistent_log.get_voted_for()
            
            # Check if we've already voted for someone else in this term
            if voted_for is not None and voted_for != request.candidate_id:
                return raft_pb2.RequestVoteResponse(term=current_term, vote_granted=False)
            
            # Check if candidate's log is at least as up-to-date as ours
            last_log_index = self.persistent_log.get_last_log_index()
            last_log_term = self.persistent_log.get_last_log_term()
            
            log_ok = (request.last_log_term > last_log_term or
                     (request.last_log_term == last_log_term and
                      request.last_log_index >= last_log_index))
            
            if log_ok:
                # Grant vote
                self.persistent_log.set_voted_for(request.candidate_id)
                self._reset_election_timer()
                return raft_pb2.RequestVoteResponse(term=current_term, vote_granted=True)
            else:
                return raft_pb2.RequestVoteResponse(term=current_term, vote_granted=False)
    
    def AppendEntries(self, request, context):
        with self.state_lock:
            current_term = self.persistent_log.get_current_term()
            
            # If the leader's term is lower than our term, reject entries
            if request.term < current_term:
                return raft_pb2.AppendEntriesResponse(term=current_term, success=False)
            
            # Accept the leader (either same term or higher term)
            if request.term >= current_term:
                if self.current_leader != request.leader_id:
                    self._become_follower(request.term)
                    self.current_leader = request.leader_id
            
            # Reset election timer since we heard from the leader
            self._reset_election_timer()
            
            # Check if we have the previous log entry
            prev_log_index = request.prev_log_index
            
            if prev_log_index >= 0:
                last_log_index = self.persistent_log.get_last_log_index()
                
                # If our log is too short, we can't verify the previous entry
                if prev_log_index > last_log_index:
                    return raft_pb2.AppendEntriesResponse(term=current_term, success=False)
                
                prev_entries = self.persistent_log.get_entries(prev_log_index, prev_log_index + 1)
                if not prev_entries or prev_entries[0]["term"] != request.prev_log_term:
                    return raft_pb2.AppendEntriesResponse(term=current_term, success=False)
            
            # Convert string entries back to dictionaries
            entries = [json.loads(e) for e in request.entries]
            
            # Append entries to log
            if entries:
                success, _ = self.persistent_log.append_entries(entries, prev_log_index + 1)
                if not success:
                    return raft_pb2.AppendEntriesResponse(term=current_term, success=False)
            
            # Update commit index if leader's commit index is higher
            if request.leader_commit > self.persistent_log.get_commit_index():
                last_new_index = prev_log_index + len(entries)
                new_commit_index = min(request.leader_commit, last_new_index)
                self.persistent_log.set_commit_index(new_commit_index)
            
            return raft_pb2.AppendEntriesResponse(term=current_term, success=True)
    
    def AddNode(self, request, context):
        with self.state_lock:
            if self.state != LEADER:
                _, node_info = self.config.get_current_node()
                print("state", self.state, node_info["port"], node_info["raft_port"])
                return raft_pb2.AddNodeResponse(
                    success=False,
                    message=f"Not the leader. Current leader is {self.current_leader}"
                )
            
            node_id = request.node_id
            host = request.host
            port = request.port
            raft_port = request.raft_port
            
            # Check if node already exists
            if node_id in self.config.get_nodes():
                return raft_pb2.AddNodeResponse(
                    success=False,
                    message=f"Node {node_id} already exists"
                )
            
            # Add node to config
            self.config.add_node(node_id, host, port, raft_port)
            
            # Create a new stub for the node
            channel = grpc.insecure_channel(f"{host}:{raft_port}")
            self.node_stubs[node_id] = raft_pb2_grpc.RaftServiceStub(channel)
            
            # Initialize leader state for the new node
            last_log_index = self.persistent_log.get_last_log_index()
            self.next_index[node_id] = last_log_index + 1
            self.match_index[node_id] = 0
            
            # Submit a configuration change command
            command = {
                "type": "config_change",
                "node_id": node_id,
                "host": host,
                "port": port,
                "raft_port": raft_port,
                "action": "add"
            }
            
            # Create a new log entry
            entry = {
                "term": self.persistent_log.get_current_term(),
                "command": command
            }
            
            # Append to local log
            last_index = self.persistent_log.get_last_log_index()
            success, _ = self.persistent_log.append_entries([entry], last_index + 1)
            
            if not success:
                return raft_pb2.AddNodeResponse(
                    success=False,
                    message="Failed to append configuration change to log"
                )
            
            # Send append entries to all followers including the new node
            self._send_append_entries()
            
            return raft_pb2.AddNodeResponse(
                success=True,
                message=f"Node {node_id} added to the cluster"
            )
    
    def stop(self):
        """Stop the Raft node."""
        self.running = False
        self.server.stop(0)
        if self.election_thread.is_alive():
            self.election_thread.join(timeout=1.0)
        if self.append_entries_thread.is_alive():
            self.append_entries_thread.join(timeout=1.0)
        if self.apply_command_thread.is_alive():
            self.apply_command_thread.join(timeout=1.0)