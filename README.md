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

---

## Running the Interactive Demo

This demo simulates a 5-node distributed chat system spread across two machines. It uses a custom Raft implementation for consensus. Node 2 is configured as the initial leader.

### Prerequisites

*   Python 3.x
*   Required Python packages: `rich`, `grpcio`, `grpcio-tools`. You can install them using pip:
    ```bash
    pip install rich grpcio grpcio-tools
    ```
*   Two machines (or two separate terminal environments on one machine using localhost/different ports, though designed for two distinct IPs) accessible to each other over the network.

### Setup

1.  Clone the repository onto both machines:
    ```bash
    git clone https://github.com/NatnaelTeshome/cs2620-replication.git
    ```
2.  Navigate into the cloned directory on both machines:
    ```bash
    cd cs2620-replication
    ```

### Execution

You need to run the `distributed_demo.py` script simultaneously on both machines, telling each script which machine it is and the IP address of the *other* machine.

1.  **On Machine 1:**
    *   Open a terminal.
    *   Run the script, specifying it's machine 1 and providing the IP of machine 2:
        ```bash
        python distributed_demo.py --machine-id 1 --peer-ip <IP_ADDRESS_OF_MACHINE_2>
        ```
    *   If you omit `--peer-ip`, the script will attempt to auto-detect or prompt you for Machine 2's IP.
    *   Machine 1 will manage and run Raft nodes **1** and **2**.

2.  **On Machine 2:**
    *   Open a terminal.
    *   Run the script, specifying it's machine 2 and providing the IP of machine 1:
        ```bash
        python distributed_demo.py --machine-id 2 --peer-ip <IP_ADDRESS_OF_MACHINE_1>
        ```
    *   If you omit `--peer-ip`, the script will attempt to auto-detect or prompt you for Machine 1's IP.
    *   Machine 2 will manage and run Raft nodes **3**, **4**, and **5**.

Both scripts will start their respective local server nodes. Node 2 (running on Machine 1) will initialize as the leader. After initialization, both scripts will display an interactive command prompt.

### Interactive Commands

Once the servers are started, you can issue commands in either terminal:

*   `status`: Displays a table showing the status (Online, Offline, Starting, etc.), location (Local/Remote), and addresses of all 5 nodes in the cluster.
*   `test`: Runs a simple workload: checks/creates accounts 'alice' and 'bob', logs in as 'alice', and sends a message to 'bob'. Reports success or failure. This tests the basic functionality and consensus of the currently active cluster.
*   `fail <node_id>`: Attempts to stop the server process for the specified `<node_id>`.
    *   **Important:** This command only works for nodes running *locally* on the machine where you issue the command. (e.g., you can run `fail 1` or `fail 2` on Machine 1; `fail 3`, `fail 4`, or `fail 5` on Machine 2).
    *   By default, failing the initial leader (Node 2) is disabled. To allow this, start the script on Machine 1 with the `--fail-leader` flag:
        ```bash
        python distributed_demo.py --machine-id 1 --peer-ip <IP_MACHINE_2> --fail-leader
        ```
*   `start <node_id>`: Attempts to restart the server process for a specified `<node_id>` that was previously stopped using the `fail` command.
    *   **Important:** This command only works for nodes running *locally* on the machine where you issue the command, and only if the node is currently considered 'offline' or 'failed'.
    *   The restarted node will attempt to rejoin the cluster using its existing data directory (if any) by contacting the initial leader (Node 2).
*   `exit`: Shuts down all locally running server processes managed by the script and exits the demo cleanly. **Run this on both machines** when finished. You can also use `Ctrl+C`.

### Example Scenarios to Try

*   Run `status` to see the initial state (all nodes online, Node 2 likely leader).
*   Run `test` - it should succeed.
*   On Machine 2, run `fail 3`. Run `status` again.
*   Run `test` - it should still succeed (4 nodes remain, quorum exists).
*   On Machine 2, run `start 3`. Run `status` and wait for Node 3 to become 'Online'.
*   On Machine 1, run `fail 1`.
*   On Machine 2, run `fail 4`. Run `status`.
*   Run `test` - it should still succeed (Nodes 2, 3, 5 remain, quorum exists).
*   On Machine 2, run `fail 5`. Run `status`.
*   Run `test` - it should now **fail** (only Nodes 2 and 3 remain, quorum lost).
*   Use `start` commands on Machines 1 and 2 to bring nodes back online.
*   Run `test` again - it should succeed once quorum is re-established.
*   (Optional, requires `--fail-leader` on Machine 1): Run `fail 2` on Machine 1. Observe server logs or run `status` repeatedly to see if a new leader is elected (e.g., Node 1, 3, 4, or 5). Run `test`.

### Other Options

*   `--skip-clear`: Add this flag when starting the scripts (`python distributed_demo.py --machine-id X --skip-clear ...`) to prevent the script from deleting the `./data/node_X` directories on startup. This preserves Raft logs and state between runs.

### Exiting

Type `exit` in both terminals, or press `Ctrl+C` in both terminals to stop the demo and clean up the server processes.
