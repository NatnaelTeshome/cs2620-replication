import json
import os
import socket

def get_local_ip():
    """Get the non-localhost IP of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

class ClusterConfig:
    def __init__(self, config_file=None, node_id=None):
        self.config_file = config_file or "cluster_config.json"
        self.node_id = node_id
        self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, "r") as f:
                self.config = json.load(f)
        else:
            self.config = {
                "nodes": {},
                "cluster_id": "chat_cluster"
            }
    
    def save_config(self):
        with open(self.config_file, "w") as f:
            json.dump(self.config, f, indent=2)
    
    def get_nodes(self):
        return self.config["nodes"]
    
    def get_node(self, node_id):
        return self.config["nodes"].get(node_id)
    
    def add_node(self, node_id, host, port, raft_port):
        self.config["nodes"][node_id] = {
            "host": host,
            "port": port,
            "raft_port": raft_port
        }
        self.save_config()
    
    def remove_node(self, node_id):
        if node_id in self.config["nodes"]:
            del self.config["nodes"][node_id]
            self.save_config()
    
    def get_current_node(self):
        if self.node_id and self.node_id in self.config["nodes"]:
            return self.node_id, self.config["nodes"][self.node_id]
        return None, None
    
    def set_current_node(self, node_id):
        self.node_id = node_id