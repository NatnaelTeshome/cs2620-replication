# ChatSystem2620 Technical Documentation
---

## Table of Contents

1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Our Custom Wire Protocol Overview](#wire-protocol-overview)
   - [Supported Operations](#supported-operations)
   - [Protocol Formats](#protocol-formats)
   - [Operations and Payload Examples](#operations-and-payload-examples)
4. [API References](#api-references)
   - [Server-Side Endpoints](#server-side-endpoints)
   - [Client-Side Methods](#client-side-methods)
5. [Deployment, Configuration, and Testing](#deployment-configuration-and-testing)

---

## Project Overview

(Please refer to custom wire protocol pdf for wire protocol specific documentation)

ChatSystem2620 is a simple client-server chat application that supports real-time text messaging between users. A centralized server (implemented by `server.py` and for custom wire protocol `server_custom_wp.py`) mediates interactions between multiple clients (implemtented by `client.py` and for custom wire protocol `client_custom_wp.py`). The GUI is implemented in `gui.py`. You can instantiate the server and run the gui in multiple machines with the correct port number to see full functionality. Core functionality includes:

- **User Management:** Create accounts, log in, list users (with wildcard search), and account deletion.
- **Messaging:** Send messages to other users, with immediate delivery for online recipients and stored delivery for offline users.
- **Message Management:** Read messages (with pagination) and delete one or more messages.
- **Push Notifications:** Real-time events to notify users of new messages and message deletions.
- **Graphical Client Support:** A GUI built using Tkinter that provides an interactive chat interface.

---

## System Architecture

The overall system is divided into two major components:

1. **Server (Backend):**  
   - Utilizes an event-driven architecture powered by Python’s `selectors` (see Lecture slides from Prof. Waldo)
   - Handles account creation, login/logout, message routing, and account/message deletion.
   - Maintains mappings for message IDs and active client sessions.
   - Manages persistent data using Python’s `shelve` module.

2. **Client Library and GUI (Frontend):**  
   - Provides a client library in `client.py` that supports commands for account management, messaging, and notifications.
   - The GUI leverages the client library to offer a user-friendly chat interface.

The two components can communicate over two protocol variants: one using JSON, and the other using our custom wire protocol.

---

## Wire Protocol Overview

Communication between the client and server occurs over sockets. Each transmitted message ends with a newline (`\n`) character as a delimiter. The system supports two different wire protocols.

### Supported Operations

Each operation is identified by its `"action"` key (case-insensitive) and includes the following commands:

- **USERNAME:**  
  Checks if the provided username exists on the server. Used during the initial login/signup workflow.
  
- **CREATE:**  
  Creates a new account. The payload must include a unique username and a secure password hash
  (per the requirement, we do not send plaintext passwords over the network)
  
- **LOGIN:**  
  Authenticates a user. Provides the username and password hash. On success, the server returns the number of unread messages.
  
- **LIST_ACCOUNTS:**  
  Retrieves a list (or a paginated subset) of accounts filtered by a wildcard pattern. Supports pagination with `page_size` and `page_num`.
  
- **SEND:**  
  Sends a text message to a specified recipient. If the recipient is online, the server immediately pushes a `"NEW_MESSAGE"` event to the recipient; otherwise, the message is stored
  both in-memory and on persistent storage, and delivered the next time the recipient logs in.
  
- **READ:**  
  Retrieves messages for a given user. By default it returns all unread messages the user has received. If a specific chat partner is specified
  in the query, returns the unread messages only from that user.
  
  The results are paginated to limit the number of messages displayed to the user and the pagination is controlled with `page_size` and `page_num` parameters.
  
- **DELETE_MESSAGE:**  
  Deletes one or more messages specified by a list of message IDs.
  To delete a message, the user hovers on the message and clicks a delete button. Then, it gets deleted for both the user and the recepient. 
  
- **DELETE_ACCOUNT:**  
  Deletes the currently logged-in account.
  When account is deleted, the unread messages are displayed to the receipient. We made this decision after taking inspiration from popular chat apps like Telegram.

- **LOGOUT:**  
  Logs out the current user session.
  
- **QUIT:**  
  Closes the client connection.

### Protocol Formats

The system supports two distinct wire protocol formats:

1. **JSON-Based Protocol:**
   - **Objective:** Maximize ease of development and debugging.
   - **Characteristics:**  
     - Uses human-readable JSON objects encoded as UTF-8 strings.
     - Each JSON object is terminated by a newline character.
   - **Example (for LOGIN):**
     $$
     \{
       "action": "LOGIN",
       "username": "alice",
       "password_hash": "e3b0..."
     \}\n
     $$
   - **Usage:** Preferred for testing and prototyping despite larger message size overhead.

2. **Custom Wire Protocol:**
   - **Objective:** Achieve maximum efficiency by reducing the number of bytes sent.
   - **Characteristics:**  
     - Utilizes compact binary representations for numeric IDs and text content.
     - May employ a header with fields like "operation code", "payload length", etc.
   - **Example (Conceptual):**
     $$
     \texttt{<op-code><payload-length><payload-body>}
     $$
   - **Usage:** Designed for high-scale and low-latency scenarios.

### Operations and Payload Examples

Below are sample JSON payloads to illustrate key operations:

- **Check Username (USERNAME):**
  $$
  \{
    "action": "USERNAME",
    "username": "alice"
  \}\n
  $$

- **Create Account (CREATE):**
  $$
  \{
    "action": "CREATE",
    "username": "alice",
    "password_hash": "sha256hashvalue..."
  \}\n
  $$

- **Login (LOGIN):**
  $$
  \{
    "action": "LOGIN",
    "username": "alice",
    "password_hash": "sha256hashvalue..."
  \}\n
  $$

- **List Accounts (LIST_ACCOUNTS):**
  $$
  \{
    "action": "LIST_ACCOUNTS",
    "page_size": 10,
    "page_num": 1,
    "pattern": "*"
  \}\n
  $$

- **Send Message (SEND):**
  $$
  \{
    "action": "SEND",
    "to": "bob",
    "content": "Hello, Bob!"
  \}\n
  $$

- **Read Messages (READ):**
  - For unread messages:
    $$
    \{
      "action": "READ",
      "page_size": 5,
      "page_num": 1
    \}\n
    $$
    
  - For a conversation with a specific partner:
    $$
    \{
      "action": "READ",
      "chat_partner": "bob",
      "page_size": 5,
      "page_num": 1
    \}\n
    $$

- **Delete Message (DELETE_MESSAGE):**
  $$
  \{
    "action": "DELETE_MESSAGE",
    "message_ids": [3, 5]
  \}\n
  $$

- **Logout (LOGOUT):**
  $$
  \{
    "action": "LOGOUT"
  \}\n
  $$

- **Quit (QUIT):**
  $$
  \{
    "action": "QUIT"
  \}\n
  $$

Responses and push events follow similar conventions using JSON objects. 


## API References

### Server-Side Endpoints

Each endpoint is invoked using a JSON command containing an `"action"` key, along with any supporting parameters:

- **USERNAME:**  
  - **Input:**  
    ```json
    { "action": "USERNAME", "username": "alice" }
    ```
  - **Response:**  
    Returns a success flag and a message indicating whether the username exists.

- **CREATE:**  
  - **Input:**  
    ```json
    { "action": "CREATE", "username": "alice", "password_hash": "<hashed_value>" }
    ```
  - **Response:**  
    Confirms account creation and logs the user in.

- **LOGIN:**  
  - **Input:**  
    ```json
    { "action": "LOGIN", "username": "alice", "password_hash": "<hashed_value>" }
    ```
  - **Response:**  
    Provides confirmation along with the count of unread messages on success.

- **LIST_ACCOUNTS:**  
  - **Input:**  
    ```json
    {
      "action": "LIST_ACCOUNTS",
      "page_size": 10,
      "page_num": 1,
      "pattern": "*"
    }
    ```
  - **Response:**  
    Returns a list of matching account names and pagination details.

- **SEND:**  
  - **Input:**  
    ```json
    { "action": "SEND", "to": "bob", "content": "Hello, Bob!" }
    ```
  - **Response:**  
    Acknowledges the message with a unique ID. Also triggers a push event if the recipient is online.

- **READ:**  
  - **Input:** For unread messages:
    ```json
    { "action": "READ", "page_size": 5, "page_num": 1 }
    ```
    Or for conversation with a specific partner:
    ```json
    {
      "action": "READ",
      "chat_partner": "bob",
      "page_size": 5,
      "page_num": 1
    }
    ```
  - **Response:**  
    Provides the requested messages and updates read flags.

- **DELETE_MESSAGE:**  
  - **Input:**  
    ```json
    { "action": "DELETE_MESSAGE", "message_ids": [3, 5] }
    ```
  - **Response:**  
    Confirms deletion and pushes notifications to affected users.

- **DELETE_ACCOUNT:**  
  - **Input:**  
    ```json
    { "action": "DELETE_ACCOUNT" }
    ```
  - **Response:**  
    Confirms deletion and logs out the user.

- **LOGOUT / QUIT:**  
  - **Input:**  
    ```json
    { "action": "LOGOUT" }
    ```  
    or  
    ```json
    { "action": "QUIT" }
    ```
  - **Response:**  
    Logs the user out or terminates the connection.

### Client-Side Methods

The client library maps the above actions to high-level methods, which we then use to implement the GUI client:

- `login(username, password)`
- `create_account(username, password)`
- `account_exists(username)`
- `list_accounts(pattern, offset, limit)`
- `send_message(recipient, message)`
- `read_messages(offset, count, to_user)`
- `delete_message(message_id)`
- `delete_account(username)`
- `close()`

Each method sets up the proper payload, sends the request, waits for and processes the response.
Asynchronous push events the client receives from the server are handled via a dedicated listener thread. The listener
threads spins in a while-loop, continuously awaiting any incoming messages from the server. Any push events 
(like e.g. a new message arriving) are then handled through callback functions (e.g., 'self.on_new_message') called by the listener thread.
The callbacks then take care of, e.g. in the case of the *new message* callback, updating the client-side message cache, as well
as refreshing the UI to display the new message to the user.

---

## Deployment, Configuration, and Testing

- **Deployment:**  
  - The server is started via `server.py` and reads configuration from `config.json` (which includes settings for `HOST`, `PORT`, and the protocol choice).
  - The client application supports specifying connection details via command-line options or a configuration file.

- **Testing:**  
  - Unit tests target each endpoint using dummy clients (see `MockClient` in `client.py`).
  - GUI testing is done using a dummy MockClient class, which fakes a connection to a backend server. This massively improved our bandwidth
  in testing the GUI for this assignment.
  We have unit tests for the server and the client (please see `test_chat_server.py`, `test_client.py`, `test_custom_protocol_client.py`, and `test_custom_protocol_server.py`). You can run them by installing `pytest` and running `pytest {filename}`.

- **Logging and Debugging:**  
  - Extensive logging is enabled (with Python’s `logging` module) for network events, errors, and debugging information. For the clients,
  a `-v` flag can be specified on the command-line to enable a verbose mode, displaying a lot more useful logs.

- **Misc**:
  - Performance measurements comparing the custom protocol versus the JSON protocol are maintained in the engineering notebook.
