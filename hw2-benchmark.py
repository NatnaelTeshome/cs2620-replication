import json
import hashlib
import chat_pb2

# Importing our custom protocol encoders
from client_custom_wp import encode_login, encode_create_account, encode_send_message

# --- Benchmark Configuration ---
TEST_CASES = {
    "LOGIN": {
        "small": {"username": "u1", "password": "p1"},
        "medium": {"username": "user_medium", "password": "pass_medium!"},
        "large": {"username": "u" * 50, "password": "p" * 50},
    },
    "CREATE_ACCOUNT": {
        "small": {"username": "u1", "password": "p1"},
        "medium": {"username": "new_user_123", "password": "StrongPass!123"},
        "large": {"username": "u" * 100, "password": "p" * 100},
    },
    "SEND_MESSAGE": {
        "small": {"recipient": "b", "content": "Hi"},
        "medium": {"recipient": "user2", "content": "Hello, how are you?"},
        "large": {"recipient": "r" * 20, "content": "Lorem ipsum " * 100},
    },
}


# --- Measurement Functions ---
def measure_protobuf_size(message_type: str, case_data: dict) -> int:
    """Measure Protobuf/gRPC message size"""
    if message_type == "LOGIN":
        msg = chat_pb2.LoginRequest(
            username=case_data["username"],
            password_hash=hashlib.sha256(case_data["password"].encode()).hexdigest(),
        )
    elif message_type == "CREATE_ACCOUNT":
        msg = chat_pb2.CreateAccountRequest(
            username=case_data["username"],
            password_hash=hashlib.sha256(case_data["password"].encode()).hexdigest(),
        )
    elif message_type == "SEND_MESSAGE":
        msg = chat_pb2.SendMessageRequest(
            username="sender",  # Not used in size calculation
            to=case_data["recipient"],
            content=case_data["content"],
        )
    return len(msg.SerializeToString())


def measure_json_size(message_type: str, case_data: dict) -> int:
    """Measure JSON message size"""
    if message_type == "LOGIN":
        payload = {
            "op": "LOGIN",
            "username": case_data["username"],
            "password_hash": hashlib.sha256(case_data["password"].encode()).hexdigest(),
        }
    elif message_type == "CREATE_ACCOUNT":
        payload = {
            "op": "CREATE_ACCOUNT",
            "username": case_data["username"],
            "password_hash": hashlib.sha256(case_data["password"].encode()).hexdigest(),
        }
    elif message_type == "SEND_MESSAGE":
        payload = {
            "op": "SEND_MSG",
            "from": "sender",
            "to": case_data["recipient"],
            "content": case_data["content"],
        }
    return len(json.dumps(payload).encode())


def measure_custom_size(message_type: str, case_data: dict) -> int:
    """Measure custom protocol message size using actual encoders"""
    try:
        if message_type == "LOGIN":
            payload = {
                "username": case_data["username"],
                "password": case_data["password"],
            }
            return len(encode_login(payload))
        elif message_type == "CREATE_ACCOUNT":
            payload = {
                "username": case_data["username"],
                "password": case_data["password"],
            }
            return len(encode_create_account(payload))
        elif message_type == "SEND_MESSAGE":
            payload = {"to": case_data["recipient"], "message": case_data["content"]}
            return len(encode_send_message(payload))
    except Exception as e:
        print(f"Error encoding {message_type}: {e}")
        return 0


# --- Benchmark Execution ---
def run_benchmarks():
    results = {}

    for msg_type, cases in TEST_CASES.items():
        type_results = {}
        for case_name, case_data in cases.items():
            type_results[case_name] = {
                "JSON": measure_json_size(msg_type, case_data),
                "Protobuf": measure_protobuf_size(msg_type, case_data),
                "Custom": measure_custom_size(msg_type, case_data),
            }
        results[msg_type] = type_results

    return results


# --- Results Visualization ---
def print_results_table(results):
    print(
        "| Message Type     | Payload Size | JSON (bytes) | Custom (bytes) | Protobuf (bytes) |"
    )
    print(
        "|------------------|--------------|--------------|----------------|------------------|"
    )

    for msg_type, cases in results.items():
        first_row = True
        for case_name, sizes in cases.items():
            type_col = msg_type if first_row else ""
            row = (
                f"| {type_col:<16} | {case_name:<12} | "
                f"{sizes['JSON']:<12} | {sizes['Custom']:<14} | {sizes['Protobuf']:<16} |"
            )
            print(row)
            first_row = False


if __name__ == "__main__":
    benchmark_results = run_benchmarks()
    print_results_table(benchmark_results)
