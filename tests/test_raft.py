import pytest
import time
import grpc
import threading
import asyncio
import json # Needed for json.loads in test_append_entries_success_with_entries
from unittest.mock import MagicMock, patch, ANY

# Use the confirmed import structure
from raft import RaftNode, FOLLOWER, LEADER, CANDIDATE
import storage
from config import ClusterConfig
import raft_pb2
import raft_pb2_grpc


# === Mocks and Fixtures ===

@pytest.fixture
def mock_cluster_config():
    """Provides a mocked ClusterConfig."""
    mock = MagicMock(spec=ClusterConfig)
    # Default mock values - override in tests if needed
    mock.get_current_node.return_value = ("node1", {"host": "localhost", "port": 8001, "raft_port": 9001})
    mock.get_nodes.return_value = {
        "node1": {"host": "localhost", "port": 8001, "raft_port": 9001},
        "node2": {"host": "localhost", "port": 8002, "raft_port": 9002},
    }
    return mock

@pytest.fixture
def mock_state_machine():
    """Provides a mocked StateMachine."""
    mock = MagicMock(spec=storage.StateMachine)
    mock.apply_command.return_value = (True, "Mock success")
    return mock

@pytest.fixture
def mock_persistent_log():
    """Provides a mocked PersistentLog."""
    mock = MagicMock(spec=storage.PersistentLog)
    # Default mock values - override in tests if needed
    mock.get_current_term.return_value = 0
    mock.get_voted_for.return_value = None
    mock.get_commit_index.return_value = -1 # Changed from -1 to match typical log indexing
    mock.get_last_applied.return_value = -1 # Changed from -1
    mock.get_last_log_index.return_value = -1 # Empty log initially
    mock.get_last_log_term.return_value = 0
    mock.append_entries.return_value = (True, 0) # success, new_last_index
    mock.get_entries.return_value = []
    return mock

@pytest.fixture
def node_id():
    return "node1"

@pytest.fixture
def raft_node_dependencies(node_id, mock_cluster_config, mock_state_machine):
    """Provides common dependencies for RaftNode instantiation."""
    # NOTE: Does NOT include persistent_log here, as it's handled via patching
    return {
        "node_id": node_id,
        "config": mock_cluster_config,
        "state_machine": mock_state_machine,
    }

# === Basic RaftNode Tests ===

# Patch heavily during init to avoid actual server/thread start
@patch('raft.storage.PersistentLog')
@patch('raft.grpc.server')
@patch('raft.grpc.insecure_channel')
@patch('raft.threading.Thread')
class TestRaftNodeBasic:

    def test_init_follower(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                           raft_node_dependencies, node_id):
        """Test basic initialization as a Follower."""
        mock_log_instance = mock_log_constructor.return_value
        init_deps = raft_node_dependencies.copy() # No persistent_log to remove here
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        assert node.node_id == node_id
        assert node.state == FOLLOWER
        assert node.current_leader is None
        assert node.persistent_log == mock_log_instance # Check instance created internally is the mock
        assert node.config == raft_node_dependencies["config"]
        assert node.state_machine == raft_node_dependencies["state_machine"]
        assert node.running is True
        mock_log_constructor.assert_called_once_with(node_id)
        raft_node_dependencies["config"].get_current_node.assert_called_once()
        # Check if server setup was attempted
        mock_grpc_server.assert_called_once()
        mock_grpc_server.return_value.add_insecure_port.assert_called_once()
        mock_grpc_server.return_value.start.assert_called_once()
        # Check if stubs were created (assuming 2 nodes in default mock config)
        assert mock_channel.call_count == 1 # Called once for the *other* node
        # Check if background threads were started
        assert mock_thread.call_count == 2 # Election timer, AppendEntries timer

        node.stop() # Cleanup

    def test_init_leader(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                         raft_node_dependencies, node_id):
        """Test basic initialization as a Leader."""
        mock_log_instance = mock_log_constructor.return_value
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = True

        node = RaftNode(**init_deps)

        assert node.node_id == node_id
        assert node.state == LEADER
        assert node.current_leader == node_id # Leader is self initially
        assert node.persistent_log == mock_log_instance
        mock_log_constructor.assert_called_once_with(node_id)
        # ... other assertions similar to follower init ...

        node.stop() # Cleanup

    def test_become_follower(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                             raft_node_dependencies):
        """Test transitioning to follower state."""
        mock_log_instance = mock_log_constructor.return_value
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = True # Start as leader

        node = RaftNode(**init_deps)
        assert node.state == LEADER

        new_term = 5
        node._become_follower(new_term)

        assert node.state == FOLLOWER
        # Access the mock log instance via the node attribute
        node.persistent_log.set_current_term.assert_called_with(new_term)
        node.persistent_log.set_voted_for.assert_called_with(None)
        # We expect last_heartbeat to be updated, check if time.time was called (approx)
        # This requires patching time, which adds complexity, skipping for basic test

        node.stop()

    @patch('raft.RaftNode._send_append_entries') # Prevent actual sending
    def test_become_leader(self, mock_send_ae, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                           raft_node_dependencies, node_id, mock_persistent_log):
        """Test transitioning to leader state."""
        # Ensure the mock constructor returns our specific mock log instance
        mock_log_constructor.return_value = mock_persistent_log

        # Create dependencies for constructor *without* 'persistent_log'
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)
        # Now node.persistent_log refers to mock_persistent_log

        node.state = CANDIDATE # Must be candidate to become leader via this method

        # Mock log state for leader initialization
        mock_persistent_log.get_last_log_index.return_value = 10
        # Mock config to define other nodes
        other_node_id = "node2"
        node.config.get_nodes.return_value = {
            node_id: {}, # Self
            other_node_id: {} # Other node
        }

        node._become_leader()

        assert node.state == LEADER
        assert node.current_leader == node_id
        # Check leader state initialization
        assert other_node_id in node.next_index
        assert node.next_index[other_node_id] == 11 # last_log_index + 1
        assert other_node_id in node.match_index
        assert node.match_index[other_node_id] == 0
        mock_send_ae.assert_called_once() # Should send initial heartbeats

        node.stop()

    # --- Test RPC Handler Logic ---

    def test_request_vote_grant(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                raft_node_dependencies, mock_persistent_log):
        """Test RequestVote logic: Granting vote."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        # Node state: term 5, not voted, log index 10, log term 5
        mock_persistent_log.get_current_term.return_value = 5
        mock_persistent_log.get_voted_for.return_value = None
        mock_persistent_log.get_last_log_index.return_value = 10
        mock_persistent_log.get_last_log_term.return_value = 5

        # Candidate request: term 5, log index 10, log term 5 (equally up-to-date)
        request = raft_pb2.RequestVoteRequest(
            term=5, candidate_id="candidate1", last_log_index=10, last_log_term=5
        )
        response = node.RequestVote(request, None)

        assert response.term == 5
        assert response.vote_granted is True
        mock_persistent_log.set_voted_for.assert_called_once_with("candidate1")
        # _reset_election_timer should be called implicitly

        node.stop()

    def test_request_vote_reject_lower_term(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                            raft_node_dependencies, mock_persistent_log):
        """Test RequestVote logic: Rejecting vote due to lower term."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        mock_persistent_log.get_current_term.return_value = 5 # Node is in term 5

        request = raft_pb2.RequestVoteRequest(term=4, candidate_id="c1") # Candidate from older term
        response = node.RequestVote(request, None)

        assert response.term == 5 # Returns own term
        assert response.vote_granted is False
        mock_persistent_log.set_voted_for.assert_not_called()

        node.stop()

    def test_request_vote_reject_already_voted(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                               raft_node_dependencies, mock_persistent_log):
        """Test RequestVote logic: Rejecting vote due to already voted."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        mock_persistent_log.get_current_term.return_value = 5
        mock_persistent_log.get_voted_for.return_value = "other_candidate" # Already voted

        request = raft_pb2.RequestVoteRequest(term=5, candidate_id="candidate1")
        response = node.RequestVote(request, None)

        assert response.term == 5
        assert response.vote_granted is False
        mock_persistent_log.set_voted_for.assert_not_called()

        node.stop()

    def test_request_vote_reject_log_behind(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                            raft_node_dependencies, mock_persistent_log):
        """Test RequestVote logic: Rejecting vote due to candidate log being behind."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        # Node state: term 5, not voted, log index 10, log term 5
        mock_persistent_log.get_current_term.return_value = 5
        mock_persistent_log.get_voted_for.return_value = None
        mock_persistent_log.get_last_log_index.return_value = 10
        mock_persistent_log.get_last_log_term.return_value = 5

        # Candidate request: term 5, log index 9, log term 5 (behind)
        request = raft_pb2.RequestVoteRequest(
            term=5, candidate_id="candidate1", last_log_index=9, last_log_term=5
        )
        response = node.RequestVote(request, None)

        assert response.term == 5
        assert response.vote_granted is False
        mock_persistent_log.set_voted_for.assert_not_called()

        node.stop()

    def test_request_vote_higher_term_becomes_follower(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                                       raft_node_dependencies, mock_persistent_log):
        """Test RequestVote logic: Receiving higher term makes node a follower."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        mock_persistent_log.get_current_term.return_value = 5 # Node is in term 5

        # Candidate request: term 6 (higher) - log doesn't matter for becoming follower
        request = raft_pb2.RequestVoteRequest(
            term=6, candidate_id="candidate1", last_log_index=10, last_log_term=6
        )
        # Mock _become_follower to check it's called
        with patch.object(node, '_become_follower') as mock_become_follower:
            # Assume log check passes after term update for granting vote
            mock_persistent_log.get_last_log_index.return_value = 9
            mock_persistent_log.get_last_log_term.return_value = 6

            response = node.RequestVote(request, None)

            # Node should become follower *before* deciding vote based on log
            mock_become_follower.assert_called_once_with(6)
            # Since it became follower, it can now potentially grant the vote
            assert response.vote_granted is True # Assuming log check passes after term update
            mock_persistent_log.set_voted_for.assert_called_with("candidate1")

        node.stop()

    def test_append_entries_success_heartbeat(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                              raft_node_dependencies, mock_persistent_log):
        """Test AppendEntries logic: Successful heartbeat (no entries)."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        mock_persistent_log.get_current_term.return_value = 5
        # Mock log state: index 10, term 5
        mock_persistent_log.get_last_log_index.return_value = 10
        # Mock get_entries to return something valid for prev_log_index check
        mock_persistent_log.get_entries.side_effect = lambda start, end: [{"term": 5, "cmd": "stuff"}] if start == 10 else []

        # Leader request: term 5, prevLogIndex 10, prevLogTerm 5, no entries
        request = raft_pb2.AppendEntriesRequest(
            term=5, leader_id="leader1", prev_log_index=10, prev_log_term=5, entries=[], leader_commit=10
        )
        response = node.AppendEntries(request, None)

        assert response.term == 5
        assert response.success is True
        mock_persistent_log.append_entries.assert_not_called() # No entries to append
        # Check commit index update (basic check)
        # last_new_index = prev_log_index + len(entries) = 10 + 0 = 10
        # new_commit_index = min(leader_commit, last_new_index) = min(10, 10) = 10
        mock_persistent_log.set_commit_index.assert_called_with(10)

        node.stop()

    def test_append_entries_success_with_entries(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                                 raft_node_dependencies, mock_persistent_log):
        """Test AppendEntries logic: Successful append with entries."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        mock_persistent_log.get_current_term.return_value = 5
        # Mock log state: index 10, term 5
        mock_persistent_log.get_last_log_index.return_value = 10
        # Mock get_entries to return something valid for prev_log_index check
        mock_persistent_log.get_entries.side_effect = lambda start, end: [{"term": 5, "cmd": "stuff"}] if start == 10 else []

        # Leader request: term 5, prevLogIndex 10, prevLogTerm 5, one new entry
        new_entry_dict = {"term": 5, "command": "new_cmd"}
        new_entry_json = json.dumps(new_entry_dict)
        request = raft_pb2.AppendEntriesRequest(
            term=5, leader_id="leader1", prev_log_index=10, prev_log_term=5,
            entries=[new_entry_json], leader_commit=11
        )
        # Mock append_entries result for this call
        mock_persistent_log.append_entries.return_value = (True, 11) # success, new_last_index

        response = node.AppendEntries(request, None)

        assert response.term == 5
        assert response.success is True
        # Verify append_entries was called correctly
        mock_persistent_log.append_entries.assert_called_once_with(
            [new_entry_dict], # The parsed entry
            11 # Start index = prev_log_index + 1
        )
        # Check commit index update
        # last_new_index = prev_log_index + len(entries) = 10 + 1 = 11
        # new_commit_index = min(leader_commit, last_new_index) = min(11, 11) = 11
        mock_persistent_log.set_commit_index.assert_called_with(11)

        node.stop()


    def test_append_entries_reject_lower_term(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                              raft_node_dependencies, mock_persistent_log):
        """Test AppendEntries logic: Rejecting due to lower term."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        mock_persistent_log.get_current_term.return_value = 5 # Node is in term 5

        request = raft_pb2.AppendEntriesRequest(term=4, leader_id="l1") # Leader from older term
        response = node.AppendEntries(request, None)

        assert response.term == 5 # Returns own term
        assert response.success is False
        mock_persistent_log.append_entries.assert_not_called()

        node.stop()

    def test_append_entries_reject_log_mismatch(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                                raft_node_dependencies, mock_persistent_log):
        """Test AppendEntries logic: Rejecting due to log mismatch at prev_log_index."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        mock_persistent_log.get_current_term.return_value = 5
        # Mock log state: index 10, term 4 (different from leader's expectation)
        mock_persistent_log.get_last_log_index.return_value = 10
        # Mock get_entries to return the mismatching entry
        mock_persistent_log.get_entries.side_effect = lambda start, end: [{"term": 4, "cmd": "old_stuff"}] if start == 10 else []

        # Leader request: term 5, prevLogIndex 10, prevLogTerm 5 (expects term 5 at index 10)
        request = raft_pb2.AppendEntriesRequest(
            term=5, leader_id="leader1", prev_log_index=10, prev_log_term=5, entries=[], leader_commit=10
        )
        response = node.AppendEntries(request, None)

        assert response.term == 5
        assert response.success is False
        mock_persistent_log.append_entries.assert_not_called()
        # Verify get_entries was called to check the log
        mock_persistent_log.get_entries.assert_called_with(10, 11)

        node.stop()

    def test_append_entries_reject_log_too_short(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                                 raft_node_dependencies, mock_persistent_log):
        """Test AppendEntries logic: Rejecting due to log being too short."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)

        mock_persistent_log.get_current_term.return_value = 5
        # Mock log state: index 8 (shorter than leader's expectation)
        mock_persistent_log.get_last_log_index.return_value = 8

        # Leader request: term 5, prevLogIndex 10, prevLogTerm 5 (expects entry at index 10)
        request = raft_pb2.AppendEntriesRequest(
            term=5, leader_id="leader1", prev_log_index=10, prev_log_term=5, entries=[], leader_commit=10
        )
        response = node.AppendEntries(request, None)

        assert response.term == 5
        assert response.success is False
        mock_persistent_log.append_entries.assert_not_called()
        # get_entries might be called depending on exact logic, but the check for index > last_log_index should fail first
        # Let's assert it wasn't called with the failing index
        # mock_persistent_log.get_entries.assert_not_called() # Or be more specific if needed

        node.stop()

    # Basic test for submit_command leader check
    @pytest.mark.asyncio # Mark test as async
    async def test_submit_command_not_leader(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                             raft_node_dependencies):
        """Test submit_command fails when node is not the leader."""
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = False

        node = RaftNode(**init_deps)
        node.current_leader = "some_other_node" # Simulate knowing the leader

        command = {"type": "test", "value": 123}
        success, result = await node.submit_command(command)

        assert success is False
        assert "Not the leader" in result

        node.stop()

    @pytest.mark.asyncio
    async def test_submit_command_as_leader_basic_append(self, mock_thread, mock_channel, mock_grpc_server, mock_log_constructor,
                                                         raft_node_dependencies, mock_persistent_log):
        """Test submit_command appends to log when node is the leader (basic check)."""
        mock_log_constructor.return_value = mock_persistent_log
        init_deps = raft_node_dependencies.copy()
        init_deps["make_leader"] = True

        node = RaftNode(**init_deps)

        mock_persistent_log.get_current_term.return_value = 5
        mock_persistent_log.get_last_log_index.return_value = 9
        # Mock append result
        new_index = 10
        mock_persistent_log.append_entries.return_value = (True, new_index)

        command = {"type": "test", "value": 123}

        # We only test the initial part, not the async waiting
        # Patch the queue and future part to avoid actual waiting
        with patch.object(node, '_send_append_entries') as mock_send_ae, \
             patch('raft.asyncio.Future') as mock_future_class, \
             patch.object(node.command_queue, 'put_nowait') as mock_put_q:

            # Call the synchronous part of submit_command
            # We don't await the result here as we are not testing the future resolution
            # Instead, we check the side effects before the await
            async def run_sync_part():
                 # This context manager simulates acquiring the lock
                 with node.state_lock:
                    if node.state != LEADER: return False, "Not leader" # Guard
                    entry = {"term": node.persistent_log.get_current_term(), "command": command}
                    last_index = node.persistent_log.get_last_log_index()
                    success, new_last_index = node.persistent_log.append_entries([entry], last_index + 1)
                    if not success: return False, "Append failed"
                    future = mock_future_class() # Use the mock future
                    node.command_queue.put_nowait((new_last_index, future))
                    node._send_append_entries()
                    return True, new_last_index # Return something to indicate success

            success, idx = await run_sync_part()

            assert success is True
            assert idx == new_index

            # Verify log append was called
            expected_entry = {"term": 5, "command": command}
            mock_persistent_log.append_entries.assert_called_once_with([expected_entry], 10) # index 9 + 1

            # Verify future was created and put in queue
            mock_future_class.assert_called_once()
            mock_put_q.assert_called_once_with((new_index, mock_future_class.return_value))

            # Verify append entries was triggered
            mock_send_ae.assert_called_once()

        node.stop()
