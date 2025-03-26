# cs2620-replication

Our GitHub (public) repository for this Demo exercise can be found [here](https://github.com/NatnaelTeshome/cs2620-replication) 
([https://github.com/NatnaelTeshome/cs2620-replication](https://github.com/NatnaelTeshome/cs2620-replication)). (You are here)

The system we implement for this demo assignment is a 2-fault tolerant distributed chat application. It uses the Raft consensus algorithm to manage the state across multiple nodes, ensuring that all nodes agree on the state even in the presence of failures. 

We warrant the use of Raft for two key reasons. First, we are anticipating using Raft for our final project in this class and deemed this current design exercise as a valuable stepping stone. Second, we've explicitly verified with the TFs during OH that using Raft for this assignment is okay, albeit perhaps an overkill - we fully agree with this assessment. Despite countless hours of debugging, synchronization issues, and sleepless nights, we're glad we took on this challenge and hope it might count as 'extra credit' for the demo exercise. 

Note that *we roll our own basic implementation of Raft from scratch*, with no use of external libraries.
The main implementation of the Raft engine can be found in the root of our project's repository,
within the `raft.py` file. The log/persistence handler code can be found in `storage.py`.
The demo harness code can be found in the `demo.py` directory. We elaborate on what each of these
files does in the following section of our documentation. For a detailed documentation of
our Raft implementation, please refer to the [Documentation doc](https://github.com/NatnaelTeshome/cs2620-replication/blob/main/documentation.md).
 
Finally, our engineering notebook can be found at [here](https://github.com/NatnaelTeshome/cs2620-replication/blob/main/replication-engineering-notebook.md)
([https://github.com/NatnaelTeshome/cs2620-replication](https://github.com/NatnaelTeshome/cs2620-replication/blob/main/replication-engineering-notebook.md)).

Our grading notes for other teams at our table will be checked into this repository after demo day has concluded.



### Running cross-machine failure demo during demo day

1.  **Machine 1:**
    *   Open a terminal.
    *   Navigate to the directory containing the scripts.
    *   Run: `python distributed_demo.py --machine-id 1`
    *   It will ask for the IP address of Machine 2. Enter it.

2.  **Machine 2:**
    *   Open a terminal.
    *   Navigate to the directory containing the scripts.
    *   Run: `python distributed_demo.py --machine-id 2`
    *   It will ask for the IP address of Machine 1. Enter it.

3.  **Follow Instructions:**
    *   Both terminals will show the status of the servers they are running.
    *   The demo will run the initial workload.
    *   It will then pause and ask you to trigger the first failure (`fail 2` on Machine 1, `fail 3` (or 4 or 5) on Machine 2).
    *   After typing the `fail` commands in the respective terminals, press Enter in *both* terminals where the script prompted you.
    *   The demo will run the workload again (should succeed).
    *   It will pause again, asking Machine 2 to fail another node.
    *   Type the `fail` command on Machine 2, then press Enter in *both* terminals again.
    *   The demo will run the workload again (should succeed, as 3 nodes remain).
    *   It will pause again, asking Machine 2 to fail its last node.
    *   Type the `fail` command on Machine 2, then press Enter in *both* terminals again.
    *   The demo will run the workload one last time (should fail due to lack of quorum).
    *   Finally, type `exit` or press `Ctrl+C` in both terminals to clean up and exit.
