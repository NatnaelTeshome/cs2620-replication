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
