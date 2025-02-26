import json
import hashlib
from typing import Dict, Any

import chat_pb2

# Import your custom protocol encoders
from client_custom_wp import (
    encode_login,
    encode_create_account,
    encode_send_message,
    encode_delete_account,
    encode_list_accounts,
    encode_read_messages,
    encode_delete_message,
    encode_check_username,
    encode_quit,
)

# --- Benchmark Configuration ---
TEST_CASES: Dict[str, Dict[str, Dict[str, Any]]] = {
    "LOGIN": {
        "empty": {"username": "", "password": ""},
        "small": {"username": "u1", "password": "p1"},
        "medium": {"username": "user_medium", "password": "pass_medium!"},
        "large": {"username": "u" * 50, "password": "p" * 50},
    },
    "CREATE_ACCOUNT": {
        "empty": {"username": "", "password": ""},
        "small": {"username": "u1", "password": "p1"},
        "medium": {"username": "new_user_123", "password": "StrongPass!123"},
        "large": {"username": "u" * 100, "password": "p" * 100},
    },
    "SEND_MESSAGE": {
        "empty": {"recipient": "", "content": ""},
        "small": {"recipient": "b", "content": "Hi"},
        "medium": {"recipient": "user2", "content": "Hello, how are you?"},
        "large": {"recipient": "r" * 20, "content": "Lorem ipsum " * 100},
    },
    "DELETE_ACCOUNT": {
        "empty": {},
        "typical": {"confirmation": "delete"},  # Example extra field
    },
    "LIST_ACCOUNTS": {
        "empty": {"pattern": "", "page_size": 0, "page_num": 0},
        "small": {"pattern": "u*", "page_size": 10, "page_num": 1},
        "large": {"pattern": "*user*", "page_size": 100, "page_num": 5},
    },
    "READ_MESSAGES": {
        "empty": {"page_size": 0, "page_num": 0, "chat_partner": ""},
        "small": {"page_size": 10, "page_num": 1, "chat_partner": "user1"},
        "large": {"page_size": 100, "page_num": 2, "chat_partner": "user" * 10},
    },
    "DELETE_MESSAGE": {
        "empty": {"message_ids": []},
        "small": {"message_ids": [1]},
        "large": {"message_ids": list(range(1, 101))},  # 100 message IDs
    },
    "CHECK_USERNAME": {
        "empty": {"username": ""},
        "small": {"username": "u1"},
        "large": {"username": "very_long_username" * 10},
    },
    "QUIT": {"empty": {}},
}


# --- Protobuf Measurement Functions ---


def get_protobuf_message(message_type: str, case_data: dict) -> Any:
    # For these Protobuf messages, some fields are hardcoded (e.g., username="user")
    if message_type == "LOGIN":
        return chat_pb2.LoginRequest(
            username=case_data["username"],
            password_hash=hashlib.sha256(case_data["password"].encode()).hexdigest(),
        )
    elif message_type == "CREATE_ACCOUNT":
        return chat_pb2.CreateAccountRequest(
            username=case_data["username"],
            password_hash=hashlib.sha256(case_data["password"].encode()).hexdigest(),
        )
    elif message_type == "SEND_MESSAGE":
        return chat_pb2.SendMessageRequest(
            username="sender",
            to=case_data["recipient"],
            content=case_data["content"],
        )
    elif message_type == "DELETE_ACCOUNT":
        # Protobuf expects a username even if our custom encoder ignores extra data.
        return chat_pb2.DeleteAccountRequest(username="user")
    elif message_type == "LIST_ACCOUNTS":
        return chat_pb2.ListAccountsRequest(
            username="user",
            pattern=case_data["pattern"],
            page_size=case_data["page_size"],
            page_num=case_data["page_num"],
        )
    elif message_type == "READ_MESSAGES":
        return chat_pb2.ReadMessagesRequest(
            username="user",
            page_size=case_data["page_size"],
            page_num=case_data["page_num"],
            chat_partner=case_data["chat_partner"] or None,
        )
    elif message_type == "DELETE_MESSAGE":
        return chat_pb2.DeleteMessageRequest(
            username="user",
            message_ids=case_data["message_ids"],
        )
    elif message_type == "CHECK_USERNAME":
        return chat_pb2.CheckUsernameRequest(username=case_data["username"])
    elif message_type == "QUIT":
        return chat_pb2.LogoutRequest(username="user")
    raise ValueError(f"Unknown message type: {message_type}")


def measure_protobuf_size(message_type: str, case_data: dict) -> int:
    msg = get_protobuf_message(message_type, case_data)
    return len(msg.SerializeToString())


# --- JSON Measurement Functions ---


def get_json_payload(message_type: str, case_data: dict) -> Dict[str, Any]:
    if message_type == "LOGIN":
        return {
            "op": "LOGIN",
            "username": case_data["username"],
            "password_hash": hashlib.sha256(case_data["password"].encode()).hexdigest(),
        }
    elif message_type == "CREATE_ACCOUNT":
        return {
            "op": "CREATE_ACCOUNT",
            "username": case_data["username"],
            "password_hash": hashlib.sha256(case_data["password"].encode()).hexdigest(),
        }
    elif message_type == "SEND_MESSAGE":
        return {
            "op": "SEND_MESSAGE",
            "to": case_data["recipient"],
            "message": case_data["content"],
        }
    elif message_type == "DELETE_ACCOUNT":
        # Incorporate an extra field if present (e.g. confirmation)
        return {
            "op": "DELETE_ACCOUNT",
            "confirmation": case_data.get("confirmation", ""),
        }
    elif message_type == "LIST_ACCOUNTS":
        return {
            "op": "LIST_ACCOUNTS",
            "pattern": case_data["pattern"],
            "page_size": case_data["page_size"],
            "page_num": case_data["page_num"],
        }
    elif message_type == "READ_MESSAGES":
        return {
            "op": "READ_MESSAGES",
            "page_size": case_data["page_size"],
            "page_num": case_data["page_num"],
            "chat_partner": case_data["chat_partner"],
        }
    elif message_type == "DELETE_MESSAGE":
        return {"op": "DELETE_MESSAGE", "message_ids": case_data["message_ids"]}
    elif message_type == "CHECK_USERNAME":
        return {"op": "CHECK_USERNAME", "username": case_data["username"]}
    elif message_type == "QUIT":
        return {"op": "QUIT"}
    else:
        raise ValueError(f"Unknown message type: {message_type}")


def measure_json_size(message_type: str, case_data: dict) -> int:
    payload = get_json_payload(message_type, case_data)
    return len(json.dumps(payload).encode("utf-8"))


# --- Custom Protocol Measurement Functions ---


def measure_custom_size(message_type: str, case_data: dict) -> int:
    try:
        # For each message type, call the appropriate custom encoder.
        if message_type == "LOGIN":
            payload = {
                "username": case_data["username"],
                "password": case_data["password"],
            }
            data = encode_login(payload)
        elif message_type == "CREATE_ACCOUNT":
            payload = {
                "username": case_data["username"],
                "password": case_data["password"],
            }
            data = encode_create_account(payload)
        elif message_type == "SEND_MESSAGE":
            payload = {"to": case_data["recipient"], "message": case_data["content"]}
            data = encode_send_message(payload)
        elif message_type == "DELETE_ACCOUNT":
            data = encode_delete_account(case_data)
        elif message_type == "LIST_ACCOUNTS":
            data = encode_list_accounts(case_data)
        elif message_type == "READ_MESSAGES":
            data = encode_read_messages(case_data)
        elif message_type == "DELETE_MESSAGE":
            data = encode_delete_message(case_data)
        elif message_type == "CHECK_USERNAME":
            data = encode_check_username(case_data)
        elif message_type == "QUIT":
            data = encode_quit()
        else:
            raise ValueError(f"Unknown message type: {message_type}")
        return len(data)
    except Exception as e:
        print(f"Error encoding {message_type} with data={case_data}: {e}")
        return 0


# --- Benchmark Runner ---


def run_benchmarks() -> Dict[str, Dict[str, Dict[str, Any]]]:
    results = {}
    for msg_type, cases in TEST_CASES.items():
        results[msg_type] = {}
        for case_name, case_data in cases.items():
            json_size = measure_json_size(msg_type, case_data)
            custom_size = measure_custom_size(msg_type, case_data)
            proto_size = measure_protobuf_size(msg_type, case_data)
            custom_ratio = custom_size / json_size if json_size > 0 else 0
            proto_ratio = proto_size / json_size if json_size > 0 else 0
            results[msg_type][case_name] = {
                "JSON": json_size,
                "Custom": custom_size,
                "Custom/JSON": round(custom_ratio, 2),
                "Protobuf": proto_size,
                "Protobuf/JSON": round(proto_ratio, 2),
            }
    return results


# --- Results Table Printer ---


def print_results_table(results: Dict[str, Dict[str, Dict[str, Any]]]) -> None:
    header = (
        "| Message Type     | Case     | JSON (bytes) | Custom (bytes) | "
        "Custom/JSON | Protobuf (bytes) | Protobuf/JSON |"
    )
    separator = (
        "|"
        + "-" * 18
        + "|"
        + "-" * 10
        + "|"
        + "-" * 14
        + "|"
        + "-" * 16
        + "|"
        + "-" * 13
        + "|"
        + "-" * 18
        + "|"
        + "-" * 16
        + "|"
    )
    print(header)
    print(separator)
    for msg_type, cases in results.items():
        first_row = True
        for case_name, sizes in cases.items():
            type_cell = msg_type if first_row else ""
            line = (
                f"| {type_cell:<16} | {case_name:<8} | {sizes['JSON']:<12} | "
                f"{sizes['Custom']:<14} | {sizes['Custom/JSON']:<11} | "
                f"{sizes['Protobuf']:<16} | {sizes['Protobuf/JSON']:<14} |"
            )
            print(line)
            first_row = False


if __name__ == "__main__":
    benchmark_results = run_benchmarks()
    print_results_table(benchmark_results)
