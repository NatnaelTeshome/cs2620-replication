Below please find attached our engineering/lab notebook entries.
Our GitHub (public) repository for this Demo exercise can be found [here](https://github.com/NatnaelTeshome/cs2620-replication)
([https://github.com/NatnaelTeshome/cs2620-replication](https://github.com/NatnaelTeshome/cs2620-replication)).

Our documentation for the project can be found in the `documentation.md` [file](https://github.com/NatnaelTeshome/cs2620-replication/blob/main/documentation.md) in the root directory of our repo.

---
Date: Tue Mar 25 19:56 (Natnael)

A bunch of minor tweaks. Commit: 7c2b629e9242e759ce88961092ce0d01fb6653bf

What I did:

    Commented out a bunch of dead code that added node responses.
    `ChatServer.start_server` now returns a boolean flag indicating whether it succeeded or not in
    joining a cluster (or becoming the leader node)
    
    Merged my changes with main code (8c44b4abb11600785389174d920b5bc19066fbbe)



---

Date: Tue Mar 25 16:52 (Natnael)

The demo is now working, and the fault tolerance finally doesn't fail!
Commit hash: 0e292c81180820e68866d94f634b2826d94e608b

What I tried doing:

    Configured everything with the proper number of replicas
    (see `cluster_config.json` files in our repo). We're now able to start/kill the desired number of servers.
    I was finally able to uncomment some of the previously failing test cases.
    
TODOs:

    There still seems to be minor issues with the demo + we aren't properly visualizing how our persistence
    works across nodes. We thought about this before, but would printing to the terminal from different nodes
    be enough?

---

Date: Tuesday Mar 25 (Michal)

Added a small flag to skip redundant data directory clear call,
which resulted in annoying double printing of logs to the terminal. 
Relevant commit: 02d989d503727a2ae91b9c17ee59f15cbf32df42

What I did:

    Added a command-line flag --skip-clear to the demo application.
    Added .gitignore entries to skip __pycache__ to avoid useless commit diffs (we had a bunch of these checked in...)


---

Date: Tue Mar 25 07:08 (Natnael)

Finally Resolved a deadlock (using the async library). Commit Hash: 12b12a8c6f9c7421986d4765170b195945a4a721

What I tried doing:

    Fine tuned the command application and commit index to properly use async so that client submission works. The problem was that I was blocking at incorrect times, leading to the threads never resolving correctly.

Questions for OH:

    Is it safe to be doing this? How do we make sure I'm not messing up and potentially introducing new 
    race conditions? We will test thoroughly but how many thousands of times will we need to test...

---


Date: Tuesday Mar 25 (Michal)

Added a new protobuf. Relevant commit: 8ef4483bac3ca0505698dfb7a59ef48a8ee68d70.
This makes it so we can update the machine config with rpc.

TODO:
    Are we actually using all the fields in our protobuf definitions?

---

Date: Tuesday Mar 25 (Michal)

Wrote a bunch of boilerplate code for the leader to be able to broadcast their state.

Prepared for the ability for leaders to broadcast their state. This will likely involve the leader regularly broadcasting their identity and term number.

What I tried doing:

    Added protocol buffer entries : nodes should now be able to communicate their raft state!
    Not much code touched, just tons of boilerpalte for later.




---

Date: Mon Mar 24 22:01 (Natnael)

More debugging threadsthreadsthreads. Concurrent appends seemed to be failing. 
The relevant Commit hash : 4761734166daa9cf3847d2fa667a7fff8c1411ef

What I tried doing:

    Went through the locking logic for background threads (threads accessing persistent storage). Turned out we were missing
    a few lock acquirals in critical sections of the code. Also added code to ensure the leader always waits for the result
    of a command before rturning to a client.

Problems:

    Some operations are taking very long, mostly when sending many small message. Presumably, this is due to our
    coarse-grained locking approach? Need to profile our app at some point, but this isn't our priority for now:
    for demo day we care far more about functionality and it actually working than raw performance

Questions for OH:
    1) ...was Raft the right choice?
    2) How do we test persistence? By showing logs? Is there a better way


---

Date: Monday Mar 24 (Michal)

State Machine code can now propagate errors to the Raft layer so that it can be handled and (hopefully),
bubbled back to the client. The Raft layer then communicates these back to the test code.

TODOs:

    Need to figure out what the right response format should be... If every client sends a check request to the raft cluster (or any request for that matter), and the cluster didn't manage to commit it, should the clients keep retrying? or, should there be a timeout? def need to have a consistent semantic here.


---

Date: Mon Mar 24 02:02 (Natnael)

Working on the servers' demo harness cdode initialization (proper ports etc.)

What I tried doing:

    Updated how start_server launches the demo application so that ports are initialized correctly. I belive 
    this was causing many randoms errors/crashes during cluster setup and inter-node communication.
    Minor change to the README.md to update it to the current name. Commit: 3bb239078daecd79f70c6e4f83230fbd80a5fa36

Problems:

    It's, unsurprisingly, hard to end-to-end test. We need to look into doing this somehow more deterministically if possible,
    especially since we don't want the Wednesday demo to fail.

TODOs:

    Implement proper leader redirection in the client library for fault tolerance.
    Need to implement integration with the client so it can properly connect to new clusters or detect leader changes.



---

Date: Sun Mar 23 23:55 (Natnael)

Added Futures / asyncio logic for synchronization, so that the leader node is more reliable.
See commit 3a78e146eca52c78d6bc5c411acdb71f9560c192 for details

Problems:

    We still seem to be running into deadlock issues within `raft.py`?

TODOs:

    The leader still seems to have a bunch of reliability issues, which need debugging
    internal: take into account the leader sending a message to itself. refer to Youtube
    talk about election timeout design decision
    making the functions synchronous vs asynchronous
    internal: do we even run_apply_command?
    internal: run_apply command is running forever. We shouldn’t use this in any call to submit_command unless run_apply_command is running on a separate thread.

Questions for OH (tmrw hopefully):

    Once committed, the leader applies the entry to its state machine immediately. Followers, however, update their commit index when they learn of the committed entry (typically through heartbeat messages from the leader) and then apply it to their state machines asynchronously. This means there can be a short delay between the leader applying the entry and a follower doing so.

    ask about read vs write distributions over servers

    The main assignment doesn't require that any of the servers be able to re-join after failure-- we are talking about 2-fault tolerant in the face of crash or failstop, both defined as the server failing and not rejoining.

    The extra credit is to deal with the re-join case. We should ask about how leaders are determined in the system-- if the leader can crash, then we want to re-join, it needs to know that it is no longer the leader as part of the re-join mechanism. Using the smallest process id is fine for selecting a leader, but determining the leader needs some other mechanism once the system is running.

    For adding node, we can assume initially a new node to be added has the host and port of all the servers that started the cluster? Is that valid?  This would theoretically  allow us to try again using multiple nodes in case the leader fails and never restarts.

    Decide how we can add a new node if the node we connect to (the former leader or whatever) fails. We should retry.




---

Date: Thursday Mar 20 (Michal)

Adding the ability to dynamically introduce nodes into the existing raft cluster (our hopefully working extra credit!)

What I tried doing:

    Implemented the AddNode RPC to allow an existing leader to add a new node to the cluster. This involves broadcasting a configuration change to the existing cluster members. I also tried to make the configuration process
    more general/dynamic, using a custom `ClusterConfig` class.

Problems:

    Node addition is currently not consensus controlled. The leader simply adds the node and broadcasts it. We might need to force every node to ACK such operation.. Currently, there is no explicit mechanism for log replication to the new node during or after the add operation. Will need to add that.

TODOs:

    New node needs to sync its state upon joining. We need some sort of log transfer mechanism from the leader? 
    Need to make sure the demo app handles adding new nodes and tests this functionality, including node failures.
    The addition of the node should be consensus controlled (!!!) and all other members must acknowledge it. 
    I also want to implement the feature Nati talked about before, where we will perform some sort of snapshotting/checkpoints after reaching consensus (see previous engineering lab entry0.

---

Date: Thu Mar 20 16:37 (Natnael)

Took care of prototyping today.
Initial implementation of the Raft consensus algorithm and demo code. We start off with our previous
design exercise as a base, hence the similarities in our repos structures. 
Relevant Commit hash: 1905ac428d1f5acc32001f83e685f008270b6171

What I tried doing:

    Implemented core Raft consensus mechanics based on the original paper I found [here](https://raft.github.io/raft.pdf), including leader election using randomized election timeouts and RequestVote RPCs, and followers sending heartbeats to maintain leadership.
    Added persistent storage of the Raft log, metadata (current term, votedFor, commitIndex, lastApplied) via simple appending of JSON-serialized log entries. Also needed a lot of boilerplate code to initialize persistent state.
    Implemented client command submission and replication using AppendEntries to synchronize log entries across the cluster.
    Created a super basic initial demo code for a simplified chat application showcasing account creation, message transfer, and basic interaction with the Raft layer.

Problems:
    
    The main problem is... it doesn't work. Perhaps using Raft was overambitious on our end? The demo code
    runs mostly okay but none of the fault tolerance works. There seems to be multiple race conditions which
    we will need to resolve (mostly log access & raft node's internal state updates).

TODOs:

    We have yet to implement a proper persistence layer and recovery from node failures. How do we 
    load / replay log files after a failure? Need to address the race conditions mentioned before... we will
    probably go with a coarse-grained state lock appraoch : simple and dumb, but it will significantly save on our
    engineering / debugging time. I worry about performance though.... We will eventually need to write a test suite,
    so will get started on that in parallel as I am working o features...
    A thing to consider: what if we periodically took snapshots of system state so we don't have to replay the *entire* log
    during recovery? 

### Commit list

 1. **Merge branch 'main' of https://github.com/NatnaelTeshome/cs2620-replication**:
    This commit merges the 'main' branch from the specified remote repository into
    the current branch. This is a standard Git operation to integrate changes
    from one branch into another.
 2. **temp**: This commit includes temporary changes related to cluster joining
    and server restarting, specifically modifying the `start_server` and
    `restart_server` functions in `chat_server.py` and `demo.py`. These changes
    involve ensuring a server successfully joins the cluster before proceeding
    and managing server restarts in a loop. Furthermore, the commit adjusts the
    handling of node additions in `raft.py`, allowing nodes to be re-added even
    if they previously existed, and postpones the actual appending of
    configuration changes to the log.
 3. **fault tolerance demo working**: This commit marks the achievement of a
    working fault tolerance demonstration within the distributed chat system.
    Changes span multiple files, indicating a holistic effort to ensure the
    system remains operational despite node failures. It features new cluster
    configurations for 4 and 5 nodes, persistence of data to logs, refactors,
    and debugging.
 4. **Skip redundant data directory clear call**: This commit optimizes the demo
    by skipping a redundant call to clear the data directory, controlled by a
    new command-line argument `--skip-clear`. This allows for faster demo runs
    when starting from an existing state is desired, while ignoring
    `__pycache__` folders.
 5. **Deadlock resolved**: This commit resolves a deadlock issue, requiring
    modifications to `raft.py` to fine-tune thread synchronization and state
    management, notably in the command application and commit index verification
    logic. It also included several binary file changes and typo fixes.
 6. **new raft proto**: This commit introduces changes to the Raft protocol
    buffer definition (`raft.proto`) and regenerates the corresponding Python
    files (`raft_pb2.py`, `raft_pb2_grpc.py`). It adds a new
    `UpdateClusterConfig` RPC to facilitate cluster configuration updates, along
    with associated request and response messages, enhancing the cluster
    management capabilities of the Raft implementation.
 7. **Merge branch 'main' of https://github.com/NatnaelTeshome/cs2620-replication**:
    This commit merges the 'main' branch from the specified remote repository
    into the current branch, resolving any conflicts and integrating new
    changes.
 8. **initial node addition communication**: This commit lays the groundwork for
    node addition functionality by establishing initial communication channels
    between Raft nodes, defining the necessary protocol buffer messages
    (`AddNodeRequest`, `AddNodeResponse`) in `raft.proto`, and implementing the
    corresponding RPC service methods in `raft.py`. This commit enables a Raft
    leader to accept and process requests to add new nodes to the cluster.
 9. **multithreading debugging**: This commit addresses multithreading issues by
    introducing granular locking mechanisms and improving state management
    within the Raft consensus algorithm. Notably, the leader now awaits command
    results using futures, thus enhancing its reliability.
 10. **state machine response tried**: This commit attempts to integrate state
     machine responses into the Raft consensus algorithm to improve the
     reliability and feedback mechanisms of operations performed within the
     distributed system. Also involves changes in the client side to improve the
     `account_exists` call.
 11. **Update README.md**: This commit updates the README file to reflect the
     project name as "cs2620-replication".
 12. **initializing servers demo worked**: This commit represents a milestone
     where the basic initialization of the Raft servers in the demo setup is
     confirmed to be working. This involves ensuring that servers start
     correctly and can form a cluster, laying the foundation for more complex
     distributed system operations.
 13. **in-memory state operations updated**: This commit focuses on updating the
     in-memory state operations within the Raft implementation. Refactors code
     with explicit thread management, resolving race conditions, etc.
 14. **add node functionality**: This commit introduces add node functionality,
     enabling dynamic scaling of the chat system. The commit includes a fully
     functional implementation of Raft consensus along with demo code showcasing
     the key features of this consensus algorithm (account creation, message
     transfer, and fault tolerance).






Fault-Tolerant Distributed Chat System

We design and implement a persistent, fault-tolerant chat application that can survive up to 2 node failures. This implementation will build on the provided gRPC chat service code and add distributed consensus to ensure reliability.
System Design Overview
The redesigned system will use the Raft consensus algorithm to implement fault tolerance. Raft provides:

Leader Election - One node is elected as the leader and coordinates all writes
Log Replication - All changes are logged and replicated across nodes
Safety Guarantees - Ensures consistency even during network partitions

Each node will maintain its own persistent storage, and the system will continue to function as long as a majority of nodes are operational.
Key Components
Let's create the following files:

raft.proto - Protocol buffer definitions for Raft consensus
config.py - Cluster configuration management
storage.py - Persistent storage for logs and state
raft.py - Raft consensus implementation
chat_server.py - Main chat server with Raft integration
demo.py - Script to demonstrate the system



# Understanding the Two Persistence Layers in Raft

## The Two Types of Persistence

Our system maintains two separate persistence mechanisms, each serving a different purpose:

### 1. Raft Log Persistence (in PersistentLog class)

- *Purpose*: Records all commands in order for consensus
- *Content*: Operation log entries with terms
- *Usage*: Replication, leader election, crash recovery
- *Consensus-critical*: Must be consistent across nodes

### 2. State Machine Database (in StateMachine class)

- *Purpose*: Stores the current application state
- *Content*: Accounts, messages, conversations
- *Usage*: Efficient reads, writes, and queries
- *Result of consensus*: Derived by applying log entries

## Why Both Are Necessary

It might seem redundant, but this dual-layer approach is standard in Raft implementations for several important reasons:

### Performance Reasons

*Without the database:*


Copy
# Every time a node restarts
1. Load log from disk (could be millions of entries)
2. Replay every command from the beginning of time
3. Finally ready to serve requests (after significant delay)



*With the database:*


Copy
# When a node restarts
1. Load database directly (current state)
2. Only replay log entries since last database sync
3. Ready to serve requests quickly



### Follower Handling of Read Queries

- *Forwarding Requests:*
    
    Followers generally do not serve linearizable read queries on their own because their state might be stale. Instead, if a follower receives a read request, it will typically forward the request to the leader.
    
- *Stale or Non-Linearizable Reads:*
    
    In some scenarios where applications can tolerate slightly out-of-date data, followers might be allowed to serve read queries. However, this approach sacrifices strong consistency guarantees and is not part of the default linearizable Raft protocol.
    

check:

*Asynchronous Application:*
