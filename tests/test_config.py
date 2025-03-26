import json
import os
import socket
import pytest
from unittest.mock import patch, MagicMock
from config import get_local_ip, ClusterConfig


# === Fixtures ===

@pytest.fixture
def temp_config_dir(tmp_path):
    """Provides a temporary directory for config files."""
    return tmp_path

@pytest.fixture
def default_node_id():
    """Provides a consistent node ID for tests."""
    return "test_node_1"

@pytest.fixture
def default_config_filename(default_node_id):
    """Provides the default config filename based on node_id."""
    return f"cluster_config_{default_node_id}.json"

@pytest.fixture
def explicit_config_filename():
    """Provides an explicit config filename."""
    return "my_special_config.json"


# === Tests for get_local_ip ===

@patch('config.socket.socket')
def test_get_local_ip_success(mock_socket_constructor):
    """Test get_local_ip when socket connection succeeds."""
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = ('192.168.1.100', 12345)
    mock_socket_constructor.return_value.__enter__.return_value = mock_socket_instance # If used as context manager
    mock_socket_constructor.return_value = mock_socket_instance # If used directly

    ip = get_local_ip()

    assert ip == '192.168.1.100'
    mock_socket_constructor.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    mock_socket_instance.connect.assert_called_once_with(('10.255.255.255', 1))
    mock_socket_instance.getsockname.assert_called_once()
    mock_socket_instance.close.assert_called_once() # Verify socket is closed

@patch('config.socket.socket')
def test_get_local_ip_failure(mock_socket_constructor):
    """Test get_local_ip when socket connection fails."""
    mock_socket_instance = MagicMock()
    mock_socket_instance.connect.side_effect = socket.error("Connection failed")
    mock_socket_constructor.return_value.__enter__.return_value = mock_socket_instance
    mock_socket_constructor.return_value = mock_socket_instance

    ip = get_local_ip()

    assert ip == '127.0.0.1'
    mock_socket_constructor.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    mock_socket_instance.connect.assert_called_once_with(('10.255.255.255', 1))
    mock_socket_instance.getsockname.assert_not_called() # Should not be called on failure
    mock_socket_instance.close.assert_called_once() # Verify socket is closed even on failure


# === Tests for ClusterConfig ===

class TestClusterConfig:

    def test_init_no_file_default_name(self, temp_config_dir, default_node_id, default_config_filename):
        """Test init when config file doesn't exist, using default naming."""
        config_path = temp_config_dir / default_config_filename
        assert not config_path.exists()

        cc = ClusterConfig(node_id=default_node_id, config_file=str(config_path))

        assert cc.node_id == default_node_id
        assert cc.config_file == str(config_path)
        assert cc.config == {
            "nodes": {},
            "cluster_id": "chat_cluster"
        }
        # File should not be created on init/load, only on save
        assert not config_path.exists()

    def test_init_no_file_explicit_name(self, temp_config_dir, explicit_config_filename):
        """Test init when config file doesn't exist, using explicit name."""
        config_path = temp_config_dir / explicit_config_filename
        assert not config_path.exists()

        cc = ClusterConfig(config_file=str(config_path), node_id="some_node") # node_id shouldn't affect explicit name

        assert cc.config_file == str(config_path)
        assert cc.config == {
            "nodes": {},
            "cluster_id": "chat_cluster"
        }
        assert not config_path.exists()

    def test_init_with_existing_file(self, temp_config_dir, default_node_id, default_config_filename):
        """Test init when config file exists."""
        config_path = temp_config_dir / default_config_filename
        existing_data = {
            "nodes": {
                "node1": {"host": "1.1.1.1", "port": 8000, "raft_port": 9000},
                "node2": {"host": "2.2.2.2", "port": 8001, "raft_port": 9001}
            },
            "cluster_id": "existing_cluster"
        }
        with open(config_path, "w") as f:
            json.dump(existing_data, f)

        cc = ClusterConfig(node_id=default_node_id, config_file=str(config_path))

        assert cc.node_id == default_node_id
        assert cc.config_file == str(config_path)
        assert cc.config == existing_data

    def test_save_config(self, temp_config_dir, default_node_id, default_config_filename):
        """Test saving the configuration to a file."""
        config_path = temp_config_dir / default_config_filename
        cc = ClusterConfig(node_id=default_node_id, config_file=str(config_path))

        # Modify config in memory
        cc.config["cluster_id"] = "new_cluster_id"
        cc.config["nodes"]["node_temp"] = {"host": "temp", "port": 1, "raft_port": 2}

        cc.save_config()

        assert config_path.exists()
        with open(config_path, "r") as f:
            saved_data = json.load(f)

        assert saved_data == cc.config
        assert saved_data["cluster_id"] == "new_cluster_id"
        assert "node_temp" in saved_data["nodes"]

    def test_add_node_persistence(self, temp_config_dir, default_node_id, default_config_filename):
        """Test adding a node and verifying it's saved and reloaded."""
        config_path = temp_config_dir / default_config_filename
        cc1 = ClusterConfig(node_id=default_node_id, config_file=str(config_path))

        node_id_to_add = "new_node"
        host = "3.3.3.3"
        port = 8002
        raft_port = 9002

        cc1.add_node(node_id_to_add, host, port, raft_port)

        # Verify in memory
        assert node_id_to_add in cc1.config["nodes"]
        assert cc1.config["nodes"][node_id_to_add] == {
            "host": host, "port": port, "raft_port": raft_port
        }

        # Verify persistence by reloading
        cc2 = ClusterConfig(node_id=default_node_id, config_file=str(config_path))
        assert node_id_to_add in cc2.config["nodes"]
        assert cc2.config["nodes"][node_id_to_add] == {
            "host": host, "port": port, "raft_port": raft_port
        }

    def test_remove_node_persistence(self, temp_config_dir, default_node_id, default_config_filename):
        """Test removing a node and verifying it's saved and reloaded."""
        config_path = temp_config_dir / default_config_filename
        cc1 = ClusterConfig(node_id=default_node_id, config_file=str(config_path))

        # Add nodes first
        cc1.add_node("node_keep", "k.k.k.k", 1, 2)
        cc1.add_node("node_remove", "r.r.r.r", 3, 4)
        # Note: add_node calls save_config implicitly

        # Remove one node
        cc1.remove_node("node_remove")

        # Verify in memory
        assert "node_remove" not in cc1.config["nodes"]
        assert "node_keep" in cc1.config["nodes"]

        # Verify persistence by reloading
        cc2 = ClusterConfig(node_id=default_node_id, config_file=str(config_path))
        assert "node_remove" not in cc2.config["nodes"]
        assert "node_keep" in cc2.config["nodes"]

    def test_remove_non_existent_node(self, temp_config_dir, default_node_id, default_config_filename):
        """Test removing a node that doesn't exist."""
        config_path = temp_config_dir / default_config_filename
        cc = ClusterConfig(node_id=default_node_id, config_file=str(config_path))
        cc.add_node("node_exists", "e.e.e.e", 5, 6)
        initial_config = cc.config.copy() # Shallow copy is fine here

        # Get initial save time (or lack thereof)
        initial_mtime = None
        if config_path.exists():
             initial_mtime = config_path.stat().st_mtime

        cc.remove_node("node_does_not_exist")

        # Verify config hasn't changed
        assert cc.config == initial_config

        # Verify file wasn't unnecessarily saved again
        if initial_mtime:
            assert config_path.stat().st_mtime == initial_mtime
        else:
            # If file didn't exist initially, it shouldn't exist now either
            assert not config_path.exists()


    def test_get_nodes(self, temp_config_dir, default_node_id, default_config_filename):
        """Test retrieving the nodes dictionary."""
        config_path = temp_config_dir / default_config_filename
        cc = ClusterConfig(node_id=default_node_id, config_file=str(config_path))
        assert cc.get_nodes() == {} # Initially empty

        cc.add_node("n1", "h1", 1, 2)
        cc.add_node("n2", "h2", 3, 4)

        nodes = cc.get_nodes()
        assert isinstance(nodes, dict)
        assert "n1" in nodes
        assert "n2" in nodes
        assert nodes["n1"]["host"] == "h1"

    def test_get_node(self, temp_config_dir, default_node_id, default_config_filename):
        """Test retrieving a specific node's data."""
        config_path = temp_config_dir / default_config_filename
        cc = ClusterConfig(node_id=default_node_id, config_file=str(config_path))
        cc.add_node("n1", "h1", 1, 2)

        # Get existing node
        node_data = cc.get_node("n1")
        assert node_data == {"host": "h1", "port": 1, "raft_port": 2}

        # Get non-existent node
        node_data_none = cc.get_node("n_missing")
        assert node_data_none is None

    def test_set_current_node(self, temp_config_dir, default_config_filename):
        """Test setting the current node ID."""
        config_path = temp_config_dir / default_config_filename
        cc = ClusterConfig(node_id="initial_node", config_file=str(config_path))
        assert cc.node_id == "initial_node"

        cc.set_current_node("new_current_node")
        assert cc.node_id == "new_current_node"

    def test_get_current_node(self, temp_config_dir, default_node_id, default_config_filename):
        """Test retrieving the current node's ID and data."""
        config_path = temp_config_dir / default_config_filename
        cc = ClusterConfig(node_id=default_node_id, config_file=str(config_path))

        # Case 1: node_id is set, but node not added yet
        current_id, current_data = cc.get_current_node()
        assert current_id is None # Implementation returns None if node_id not in config["nodes"]
        assert current_data is None

        # Case 2: Add the current node
        cc.add_node(default_node_id, "my_host", 111, 222)
        current_id, current_data = cc.get_current_node()
        assert current_id == default_node_id
        assert current_data == {"host": "my_host", "port": 111, "raft_port": 222}

        # Case 3: node_id is None
        cc.set_current_node(None)
        current_id, current_data = cc.get_current_node()
        assert current_id is None
        assert current_data is None
