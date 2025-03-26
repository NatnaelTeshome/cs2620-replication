# ChatSystem2620 Technical Documentation for Replication Exercise

### 1. System Overview

The system we implement for this demo assignment is a 2-fault tolerant distributed chat application. It uses the Raft consensus algorithm to manage the state across multiple nodes, ensuring that all nodes agree on the state even in the presence of failures. 

We warrant the use of Raft for two key reasons. First, we are anticipating using Raft for our final project in this class and deemed this current design exercise as a valuable stepping stone, teaching us the intricacies of consensus algorithms. Second, while we've explicitly verified with the TFs during OH that using Raft for this assignment is okay (albeit perhaps overkill) - we fully agree with this assessment. Despite countless hours of debugging, synchronization issues, and sleepless nights, we're glad we took on this challenge and hope it might count as 'extra credit' for this demo exercise. 

Note that *we roll our own basic implementation of Raft from scratch*, with no use of external libraries.
The main implementation of the Raft engine can be found in the root of our project's repository,
within the `raft.py` file. The log/persistence handler code can be found in `storage.py`.
The demo harness code can be found in the `demo.py` directory. We elaborate on what each of these
files does in the following section of our documentation. For a detailed documentation of
our Raft implementation, please refer to the [Raft Implementation](# Detailed Explanation of Raft Implementation) at the end of this documentation file, as well as `raft.py`'s in-code comments.

### 2. Key Components

#### a. Demo Script (demo.py)

This script manages the lifecycle of the demo, including starting and stopping servers, creating clients, and executing test scenarios. It provides functions to start, kill, and restart servers, allowing dynamic cluster reconfiguration. The `run_demo` function orchestrates the entire process, from initializing the cluster to running through various test cases.

#### b. Raft Implementation (raft.py)

The `RaftNode` class is the core component that implements the Raft algorithm. It handles leader elections, log replication, and state management. Key features include:

- **Elections**: Nodes can transition between follower, candidate, and leader states. Elections are triggered if a node doesn't receive a heartbeat within a randomized timeout.
- **Log Replication**: The leader node sends append entries to followers to ensure all nodes have the same log entries, maintaining consistency.
- **State Machine**: Applies committed log entries to the system's state, handling operations like account creation and message management.

#### c. Persistent Storage (storage.py)

The `PersistentLog` class manages the storage and retrieval of log entries from disk, ensuring durability. It uses JSON for metadata and pickle for log entries. The `StateMachine` class applies these log entries to the system's state, handling user accounts and messages.

### 3. Workflow
The workflow of our Raft-based chat system is designed to ensure consistency & fault tolerance. Here's a detailed breakdown of the workflow:

#### 1. Cluster Initialization

- **Starting Servers**: The `start_server` function in `demo.py` initializes each server node. Each node runs an instance of the `RaftNode` class from `raft.py`.
  
  ```python
  def start_server(node_id, host, port, raft_port, leader_host=None, leader_port=None):
      cmd = [
          "python", "chat_server.py",
          "--node-id", node_id,
          "--host", host,
          "--port", str(port),
          "--raft-port", str(raft_port)
      ]
      if leader_host and leader_port:
          cmd.extend(["--leader-host", leader_host, "--leader-port", str(leader_port)])
      process = subprocess.Popen(cmd, universal_newlines=True)
      servers[node_id] = {
          "process": process,
          "host": host,
          "port": port,
          "raft_port": raft_port
      }
      time.sleep(5)
      return process
  ```

- **Node Communication**: Each node uses gRPC to communicate with other nodes. The `node_stubs` dictionary in `raft.py` holds the gRPC stubs for each node.

  ```python
  for nid, info in self.config.get_nodes().items():
      if nid != self.node_id:
          channel = grpc.insecure_channel(f"{info['host']}:{info['raft_port']}")
          self.node_stubs[nid] = raft_pb2_grpc.RaftServiceStub(channel)
  ```

- **Leader Election**: When a node starts, it begins as a follower. If no leader is present, it starts an election to become the leader.

#### 2. Client Interaction

- **Client Creation**: The `create_client` function in `demo.py` creates a client connected to a specific server.

  ```python
  def create_client(client_id, host, port):
      client = CustomProtocolClient(host, port, on_msg_callback=on_new_message, on_delete_callback=on_delete_message)
      clients[client_id] = client
      return client
  ```

- **Client Requests**: Clients send requests to the server, which are then processed by the Raft cluster. The `submit_command` method in `raft.py` handles submitting commands to the cluster.

  ```python
  async def submit_command(self, command):
      with self.state_lock:
          if self.state != LEADER:
              return False, "Not the leader."
          entry = {"term": self.persistent_log.get_current_term(), "command": command}
          success, new_last_index = self.persistent_log.append_entries([entry], self.persistent_log.get_last_log_index() + 1)
          if not success:
              return False, "Failed to append to local log"
          future = asyncio.Future()
          self.command_queue.put_nowait((new_last_index, future))
          self._send_append_entries()
          try:
              result = await asyncio.wait_for(future, timeout=60.0)
              return True, result
          except asyncio.TimeoutError:
              return False, "Timeout waiting for command to be committed"
  ```

- **Message Sending**: When a client sends a message, the leader node appends the message to its log and replicates it to all followers.

#### 3. Fault Tolerance

- **Node Failure Handling**: The `kill_server` function in `demo.py` can simulate a node failure. The Raft algorithm detects this and triggers an election if the leader fails.

  ```python
  def kill_server(node_id):
      if node_id in servers:
          servers[node_id]["process"].terminate()
          del servers[node_id]
  ```

- **Leader Election**: If the leader fails, the Raft algorithm elects a new leader. The `_start_election` method in `raft.py` initiates the election process.

  ```python
  def _start_election(self):
      current_term = self.persistent_log.get_current_term() + 1
      self.persistent_log.set_current_term(current_term)
      self.state = CANDIDATE
      self.persistent_log.set_voted_for(self.node_id)
      self.votes_received = {self.node_id}
      self._reset_election_timer()
      for node_id, stub in self.node_stubs.items():
          threading.Thread(target=self._request_vote_thread, args=(node_id, stub, request)).start()
  ```

- **Node Restart**: The `restart_server` function in `demo.py` allows a failed node to restart and catch up with the cluster.

  ```python
  def restart_server(node_id, host, port, raft_port, leader_host=None, leader_port=None):
      kill_server(node_id)
      while True:
          server, success = start_server(node_id, host, port, raft_port, leader_host, leader_port)
          if success:
              return server
  ```

#### 4. Persistence

- **Log Persistence**: The `PersistentLog` class in `storage.py` ensures that logs are saved to disk.

  ```python
  def append_entries(self, entries, start_index):
      if start_index < len(self.log):
          self.log = self.log[:start_index]
      self.log.extend(entries)
      self._save_log()
      return True, len(self.log) - 1
  ```

- **State Machine**: The `StateMachine` class applies committed log entries to the system's state, ensuring that the state is consistent across restarts.

  ```python
  def apply_command(self, command, log_index=None):
      if log_index is not None and cmd_type in ["create_account", "send_message", "delete_message", "delete_account"]:
          self.commands_since_snapshot += 1
          if self.commands_since_snapshot >= self.snapshot_interval:
              self._save_snapshot(log_index)
  ```

#### 5. Leader Failover

- **Leader Election**: If the leader fails, a new leader is elected, and the system continues uninterrupted. The `demo_leader_failover` function in `demo.py` tests this scenario.

  ```python
  def demo_leader_failover():
      print("\n=== STEP: LEADER FAILOVER TEST ===")
      kill_server("1")
      time.sleep(5)
      try:
          msg_id = clients["client2"].send_message("alice", "This message is sent after leader failover!")
          print(f"Message sent successfully (ID: {msg_id})")
          print("Leader failover successful! A new leader was elected.")
      except Exception as e:
          print(f"Error sending message: {e}")
  ```

#### 6. Cluster Expansion (Extra Credit)

- **Adding New Nodes**: The `AddNode` method in `raft.py` allows adding new nodes to the cluster, updating the configuration and ensuring the new node catches up with the current state.

  ```python
  def AddNode(self, request, context):
      if self.state != LEADER:
          return raft_pb2.AddNodeResponse(success=False, message=f"Not the leader. Current leader is {self.current_leader}")
      node_id = request.node_id
      host = request.host
      port = request.port
      raft_port = request.raft_port
      self.config.add_node(node_id, host, port, raft_port)
      channel = grpc.insecure_channel(f"{host}:{raft_port}")
      self.node_stubs[node_id] = raft_pb2_grpc.RaftServiceStub(channel)
      config_update = raft_pb2.ClusterConfigUpdate(
          nodes=[raft_pb2.NodeInfo(node_id=nid, host=info["host"], port=info["port"], raft_port=info["raft_port"]) for nid, info in self.config.get_nodes().items()]
      )
      response = self.node_stubs[node_id].UpdateClusterConfig(config_update)
      if not response.success:
          logging.error(f"Failed to update config on new node {node_id}: {response.message}")
      self.next_index[node_id] = 0
      self.match_index[node_id] = 0
      command = {"type": "config_change", "node_id": node_id, "host": host, "port": port, "raft_port": raft_port, "action": "add"}
      entry = {"term": self.persistent_log.get_current_term(), "command": command}
      success, _ = self.persistent_log.append_entries([entry], self.persistent_log.get_last_log_index() + 1)
      if not success:
          return raft_pb2.AddNodeResponse(success=False, message="Failed to append configuration change to log")
      self._send_append_entries()
      return raft_pb2.AddNodeResponse(success=True, message=f"Node {node_id} added to the cluster")
  ```
  

### 4. Key Features

The system is designed with several key features in mind. Below is a semi-detailed explanation of each feature, supported by relevant code snippets and explanations of how they are implemented..

---

### **Feature: Fault Tolerance**

The system is designed to tolerate failures of individual nodes while maintaining the integrity of the system. This is achieved through the Raft consensus algorithm, which ensures that the system can continue operating even if one or more nodes fail.

#### **Implementation Details:**
- **Leader Election**: If the leader node fails, Raft automatically triggers a leader election to select a new leader. This is handled by the `_start_election` method in `raft.py`.
  ```python
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

          # Send RequestVote RPCs to all other nodes
          for node_id, stub in self.node_stubs.items():
              request = raft_pb2.RequestVoteRequest(
                  term=current_term,
                  candidate_id=self.node_id,
                  last_log_index=last_log_index,
                  last_log_term=last_log_term
              )

              threading.Thread(
                  target=self._request_vote_thread,
                  args=(node_id, stub, request)
              ).start()
  ```
- **Log Replication**: The leader node replicates its log entries to all followers. If a follower is down, it can catch up with the leader's log when it restarts. This is handled by the `_send_append_entries` method in `raft.py`.
  ```python
  def _send_append_entries(self):
      """Send AppendEntries RPCs to all followers."""
      current_term = self.persistent_log.get_current_term()

      for node_id, stub in self.node_stubs.items():
          # Prepare entries to send
          next_idx = self.next_index.get(node_id, 0)
          last_log_index = self.persistent_log.get_last_log_index()

          if next_idx > last_log_index:
              entries = []
              prev_log_index = last_log_index
              prev_log_term = self.persistent_log.get_last_log_term()
          else:
              entries = self.persistent_log.get_entries(next_idx, last_log_index + 1)
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
              target=self._append_entries_per_node,
              args=(node_id, stub, request)
          ).start()
  ```

#### **Key Points:**
- The system can tolerate failures of up to `(n-1)/2` nodes, where `n` is the total number of nodes in the cluster. This is because you need a *majority* for the consensus algorithm to work!
- Failed nodes can restart and catch up with the current state of the cluster.
- The Raft algorithm ensures that the system remains consistent even in the presence of node failures.

---

### **Feature 4: Leader Failover**

The system supports automatic leader failover, ensuring that the cluster remains operational even if the current leader fails. This is a critical component of the Raft implementation.

#### **Implementation Details:**
- **Leader Election**: If the leader fails, the Raft algorithm automatically triggers an election to select a new leader. This is handled by the `_start_election` method in `raft.py`.
- **Heartbeats**: The leader sends periodic heartbeats to all followers. If a follower does not receive a heartbeat within the election timeout, it assumes the leader has failed and starts a new election.
  ```python
  def _run_append_entries(self):
      """Background thread for leaders to send AppendEntries RPCs."""
      while self.running:
          with self.state_lock:
              if self.state == LEADER:
                  self._send_append_entries()

          # Sleep for heartbeat interval
          time.sleep(HEARTBEAT_INTERVAL / 1000)
  ```
The new leader takes over the responsibility of managing the cluster and replicating logs to all followers.

---

### **Feature 5: Cluster Expansion**

The system supports dynamic addition of new nodes to the cluster. This allows the cluster to scale horizontally as needed.

#### **Implementation Details:**
- **Adding Nodes**: The `AddNode` method in `raft.py` handles the addition of new nodes to the cluster. It updates the cluster configuration and ensures the new node is integrated into the Raft consensus process.
  ```python
  def AddNode(self, request, context):
      print("Entered add node", self.node_id)
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

          # Add node to config
          self.config.add_node(node_id, host, port, raft_port)

          # Create a new stub for the node
          channel = grpc.insecure_channel(f"{host}:{raft_port}")
          self.node_stubs[node_id] = raft_pb2_grpc.RaftServiceStub(channel)

          try:
              # Create a configuration update for the new node
              config_update = raft_pb2.ClusterConfigUpdate(
                  nodes=[
                      raft_pb2.NodeInfo(
                          node_id=nid,
                          host=info["host"],
                          port=info["port"],
                          raft_port=info["raft_port"]
                      ) for nid, info in self.config.get_nodes().items()
                  ]
              )

              # Send the update to the new node
              response = self.node_stubs[node_id].UpdateClusterConfig(config_update)
              if not response.success:
                  logging.error(f"Failed to update config on new node {node_id}: {response.message}")
          except Exception as e:
              logging.error(f"Error sending cluster config to new node {node_id}: {e}")

          # Initialize leader state for the new node
          last_log_index = self.persistent_log.get_last_log_index()
          self.next_index[node_id] = 0
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
  ```
New nodes are added dynamically without requiring a restart of the cluster. The new node is integrated into the Raft consensus process, ensuring that it can participate in leader elections and log replication.

---

### **Feature 6: Persistence**

The system ensures that all data is persisted to disk, allowing the system to recover its state after a restart. This is implemented in the `PersistentLog` and `StateMachine` classes in `storage.py`.

#### **Implementation Details:**
- **Log Persistence**: The `PersistentLog` class stores log entries in a file on disk. Logs are saved periodically to ensure durability.
  ```python
  def append_entries(self, entries, start_index):
      """Append entries to log, possibly overwriting conflicting entries."""
      if start_index < len(self.log):
          # Overwrite conflicting entries
          self.log = self.log[:start_index]

      # Append new entries
      self.log.extend(entries)

      # Save to disk
      self._save_log()

      return True, len(self.log) - 1
  ```

- **State Persistence**: The `StateMachine` class periodically takes snapshots of the system's state and saves them to disk. This allows the system to recover its state after a restart.
  ```python
  def _save_snapshot(self, log_index):
      """Save current state as snapshot."""
      try:
          with open(self.snapshot_file, 'wb') as f:
              pickle.dump(self.db, f)

          with open(self.snapshot_index_file, 'w') as f:
              f.write(str(log_index))

          self.last_snapshot_index = log_index
          self.commands_since_snapshot = 0
          logging.info(f"Saved snapshot at index {log_index}")
      except Exception as e:
          logging.error(f"Error saving snapshot: {e}")
  ```

#### **Key Points:**
- Logs and state are persisted to disk (for durability)
- Snapshots are taken periodically to reduce the amount of log that needs to be replayed during recovery.
- The system can recover its state from the last snapshot and any subsequent log entries.

---

### **Feature 7: gRPC Communication**

The system uses gRPC for efficient and reliable communication between nodes. This is implemented in the `RaftNode` class in `raft.py`.

#### **Implementation Details:**
- **gRPC Server**: Each node runs a gRPC server that exposes the Raft service interface.
  ```python
  def __init__(self, node_id, config, state_machine, make_leader):
      # Initialize gRPC server
      self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
      raft_pb2_grpc.add_RaftServiceServicer_to_server(self, self.server)

      # Start the server
      self.server.add_insecure_port(f"{node_info['host']}:{node_info['raft_port']}")
      self.server.start()
  ```
- **gRPC Clients**: Nodes communicate with each other using gRPC clients. For example, the leader sends AppendEntries RPCs to followers.
  ```python
  def _send_append_entries(self):
      """Send AppendEntries RPCs to all followers."""
      current_term = self.persistent_log.get_current_term()

      for node_id, stub in self.node_stubs.items():
          # Prepare entries to send
          next_idx = self.next_index.get(node_id, 0)
          last_log_index = self.persistent_log.get_last_log_index()

          if next_idx > last_log_index:
              entries = []
              prev_log_index = last_log_index
              prev_log_term = self.persistent_log.get_last_log_term()
          else:
              entries = self.persistent_log.get_entries(next_idx, last_log_index + 1)
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
              target=self._append_entries_per_node,
              args=(node_id, stub, request)
          ).start()
  ```

---

### **Feature 8: Configuration Management**

The system supports dynamic configuration changes, such as adding or removing nodes from the cluster. This is handled by the `UpdateClusterConfig` method in `raft.py`.

#### **Implementation Details:**
- **Updating Configuration**: When a new node is added, the `UpdateClusterConfig` method is called to update the configuration of all nodes in the cluster.
  ```python
  def UpdateClusterConfig(self, request, context):
      """Update this node's cluster configuration with information from the leader."""
      try:
          # Add all nodes to our configuration
          for node_info in request.nodes:
              nid = node_info.node_id
              # Skip adding ourselves
              if nid != self.node_id:
                  # Update configuration
                  self.config.add_node(
                      nid,
                      node_info.host,
                      node_info.port,
                      node_info.raft_port
                  )

                  # Create stub for communication
                  if nid not in self.node_stubs:
                      channel = grpc.insecure_channel(f"{node_info.host}:{node_info.raft_port}")
                      self.node_stubs[nid] = raft_pb2_grpc.RaftServiceStub(channel)

          # Save configuration
          self.config.save_config()

          logging.info(f"Node {self.node_id} updated with complete cluster configuration")
          return raft_pb2.UpdateClusterConfigResponse(success=True, message="Configuration updated")
      except Exception as e:
          return raft_pb2.UpdateClusterConfigResponse(
              success=False,
              message=f"Error updating configuration: {str(e)}"
          )
  ```
Configuration changes are propagated to all nodes in the cluster, ensuring consistency.

---


# Detailed Explanation of Raft Implementation

Our Raft implementation follows the core principles of the Raft consensus algorithm as described in [the original paper by Diego Ongaro and John Ousterhout](https://raft.github.io/raft.pdf). We were also
inspired by parts of [this GoLang implementation tutorial](https://notes.eatonphil.com/2023-05-25-raft.html). The key components of our implementation, in detail, are indicated by each following header title:

## 1. State Management and Node Roles

### Server States
Each node can be in one of three states:
- **Follower**: Passive role that responds to leader's requests (default state)
- **Candidate**: Actively seeks votes to become a leader 
- **Leader**: Handles all client requests and coordinates replication

```python
# Raft node states
FOLLOWER = "FOLLOWER"
CANDIDATE = "CANDIDATE"
LEADER = "LEADER"
```

Each state has specific behaviors and transition rules. The state is maintained in the `state` variable with thread-safe access via `state_lock` (an instance of Python's [reentrant lock](https://docs.python.org/3/library/threading.html#rlock-objects)).

### Persistent State
Each node maintains persistent state that survives crashes:
- **Current Term**: Monotonically increasing counter
- **Voted For**: Candidate ID that received vote in current term (if any)
- **Log Entries**: Complete log of commands with term numbers

```python
# In persistent_log initialization
self.metadata = {
    "current_term": 0,
    "voted_for": None,
    "commit_index": 0,
    "last_applied": 0
}
```

### Volatile State
Each node also maintains volatile state that's rebuilt after crashes:
- **Commit Index**: Highest log entry known to be committed
- **Last Applied**: Highest log entry applied to state machine
- **Next Index[]**: For leaders, index of next log entry to send to each follower
- **Match Index[]**: For leaders, highest log entry known to be replicated on each follower

## 2. Leader Election

The leader election process is critical for establishing a single coordinator for the cluster.

### Election Timer
Each follower maintains an election timer that's reset whenever it receives a valid AppendEntries RPC (heartbeat) from the current leader. 
The timeout is randomized between 150-300ms to prevent split votes, which is crucial for election stability.

### Starting an Election
When the timer expires, a follower becomes a candidate and starts an election:

### Vote Counting
Votes are collected asynchronously, and once a majority is reached, the candidate becomes the leader:

### Vote Decision
A server grants a vote if:
1. The candidate's term is >= the server's current term
2. The server hasn't already voted in this term
3. The candidate's log is at least as up-to-date as the server's log

## 3. Log Replication

After a leader is elected, it handles all client requests and replicates them to followers.

### Handling Client Requests
When a client submits a command, the leader:
1. Appends the command to its log
2. Replicates the entry to followers
3. Waits for a majority to confirm replication
4. Applies the command to its state machine
5. Returns the result to the client

### AppendEntries RPC
The leader sends AppendEntries RPCs to followers to replicate log entries and send heartbeats.

### Processing AppendEntries
Followers process AppendEntries by:
1. Checking if the leader's term is current
2. Verifying log consistency
3. Appending new entries to their logs
4. Updating their commit indices

## 4. Commit Mechanism

The commit mechanism ensures that entries are only applied when safely replicated to a majority of servers.

### Advancing Commit Index
After receiving AppendEntries responses, the leader updates its commit index based on the match indices of followers.

### Applying Committed Entries
Both leaders and followers apply committed entries to their state machines.
## 5. Persistence and Recovery

Persistence is implemented through the `PersistentLog` class.
The persistence strategy ensures:
1. **Durability**: Critical state is written to disk before responding to requests
2. **Recovery**: After a crash, the node can reconstruct its state
3. **Consistency**: The log is maintained consistently with Raft guarantees

## 6. Dynamic Membership (Our Extra Credit)

The implementation supports adding new nodes to the cluster through the AddNode RPC.

The key challenges addressed in this implementation:
1. **Log Consistency**: Ensuring logs stay consistent during membership changes
2. **Configuration Distribution**: Distributing new configuration to all nodes
3. **Safety**: Maintaining safety properties during transitions


