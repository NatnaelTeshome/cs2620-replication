import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
import argparse

from client import JSONClient, MockClient

USER_COLORS = [
    "#1f77b4",  # a cool blue
    "#ff7f0e",  # a warm orange
    "#2ca02c",  # a fresh green
    "#d62728",  # a bold red
    "#9467bd",  # a muted purple
    "#8c564b",  # a natural brown
    "#e377c2",  # a soft pink
    "#7f7f7f",  # balanced gray
    "#bcbd22",  # earthy olive
    "#17becf",  # crisp cyan
]

# dummy client for illustration purposes
class client:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.session_token = None
        self.username: Optional[str] = None
        # dummy storage for testing
        self.accounts = {
            "alice": "password",
            "bob": "abc",
            "natnael": "teshome",
            "michal": "kurek",
        }
        self.messages = [
            {
                "id": 1,
                "from": "alice",
                "to": "michal",
                "timestamp": 1739064990,
                "content": "hey",
            },
            {
                "id": 2,
                "from": "bob",
                "to": "michal",
                "timestamp": 1739065050,
                "content": "hello",
            },
            {
                "id": 3,
                "from": "alice",
                "to": "michal",
                "timestamp": 1739065110,
                "content": "how r u?",
            },
            {
                "id": 4,
                "from": "michal",
                "to": "alice",
                "timestamp": 1739065170,
                "content": "i'm good, u?",
            },
            {
                "id": 5,
                "from": "alice",
                "to": "michal",
                "timestamp": 1739065230,
                "content": "doing alright",
            },
            {
                "id": 6,
                "from": "bob",
                "to": "alice",
                "timestamp": 1739065290,
                "content": "nice to hear",
            },
            {
                "id": 7,
                "from": "michal",
                "to": "bob",
                "timestamp": 1739065350,
                "content": "what's up?",
            },
            {
                "id": 8,
                "from": "bob",
                "to": "michal",
                "timestamp": 1739065410,
                "content": "not much, just chilling",
            },
            {
                "id": 9,
                "from": "alice",
                "to": "bob",
                "timestamp": 1739065470,
                "content": "same here",
            },
            {
                "id": 10,
                "from": "michal",
                "to": "alice",
                "timestamp": 1739065530,
                "content": "wanna hang out later?",
            },
        ]
        logging.debug(
            "client initialized with host '%s' and port '%s'", host, port
        )

    def account_exists(self, username: str) -> bool:
        exists = username in self.accounts
        logging.debug("checking if account '%s' exists: %s", username, exists)
        return exists

    def create_account(self, username: str, password: str) -> None:
        if username in self.accounts:
            logging.error("attempt to create an account with taken username: %s", username)
            raise Exception("username taken")
        self.accounts[username] = password
        logging.info("account '%s' created successfully", username)

    def delete_account(self, username: str) -> None:
        if username not in self.accounts:
            logging.error("attempt to delete an account that doesn't exist: %s", username)
            raise Exception("account does not exist")
        del self.accounts[username]
        logging.info("account '%s' deleted successfully", username)

    def login(self, username: str, password: str) -> int:
        if username not in self.accounts:
            logging.error("login failed, account '%s' does not exist", username)
            raise Exception("account does not exist")
        if self.accounts[username] != password:
            logging.error("login failed for account '%s' - bad password", username)
            raise Exception("bad password")
        self.session_token = "dummy_token"
        unread_count = len(self.messages)
        self.username = username
        logging.info("account '%s' logged in with %d unread messages", username, unread_count)
        return unread_count

    def list_accounts(self, pattern: str = "*", offset: int = 0, limit: int = 10) -> List[str]:
        accounts = list(self.accounts.keys())
        result = accounts[offset : offset + limit]
        logging.debug(
            "list_accounts with pattern '%s', offset %d, limit %d: %s",
            pattern,
            offset,
            limit,
            result,
        )
        return result

    def read_messages(
        self, offset: int = 0, count: int = 10, to_user: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if to_user:
            result = [
                msg
                for msg in self.messages
                if (msg["to"] == self.username and msg["from"] == to_user)
                or (msg["from"] == self.username and msg["to"] == to_user)
            ]
        else:
            result = [
                msg
                for msg in self.messages
                if msg["to"] == self.username or msg["from"] == self.username
            ]
        result = result[offset : offset + count]
        logging.debug("read_messages with offset %d, count %d: %s", offset, count, result)
        return result

    def send_message(self, recipient: str, message: str) -> None:
        if not self.session_token:
            logging.error("attempt to send message while not logged in")
            raise Exception("not logged in")
        new_msg = {
            "id": len(self.messages) + 1,
            "from": self.username if self.username else "unknown",
            "to": recipient,
            "timestamp": int(datetime.now().strftime("%s")),
            "content": message,
        }
        self.messages.append(new_msg)
        logging.info("sent message to '%s': %s: %s", recipient, message, self.messages)

    def delete_message(self, message_id: int) -> None:
        for msg in self.messages:
            if msg["id"] == message_id:
                self.messages.remove(msg)
                logging.info("deleted message with id %d", message_id)
                return
        logging.error("message with id %d not found", message_id)
        raise Exception("message not found")


# custom message line widget: shows a message and, on hover, an inline "delete" link
class message_line(tk.Frame):
    def __init__(self, parent, msg_data: Dict[str, Any], delete_callback,
                 user_color: str = "gray40", *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.msg_data = msg_data
        self.delete_callback = delete_callback

        timestamp = datetime.fromtimestamp(msg_data.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
        sender = msg_data.get("from", "unknown")
        content = msg_data.get("content", "[ERROR] No message content")
        message_text = f"[{timestamp}] {sender}: {content}"

        self.text_label = tk.Label(self, text=message_text, anchor="w", fg=user_color)
        self.text_label.grid(row=0, column=0, sticky="w")

        self.delete_label = tk.Label(self, text="delete", fg="red", cursor="hand2")
        self.delete_label.grid(row=0, column=1, sticky="e", padx=(10, 0))
        self.delete_label.grid_remove()

        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.text_label.bind("<Enter>", self.on_enter)
        self.text_label.bind("<Leave>", self.on_leave)
        self.delete_label.bind("<Enter>", self.on_enter)
        self.delete_label.bind("<Leave>", self.on_leave)
        self.delete_label.bind("<Button-1>", lambda e: self.on_delete())

        self.hide_job = None

    def on_enter(self, event=None):
        if self.hide_job is not None:
            self.after_cancel(self.hide_job)
            self.hide_job = None
        self.delete_label.grid()

    def on_leave(self, event=None):
        self.hide_job = self.after(50, self.hide_delete)

    def hide_delete(self):
        self.delete_label.grid_remove()
        self.hide_job = None

    def on_delete(self):
        self.delete_callback(self.msg_data["id"])


class chatapp(tk.Tk):
    def __init__(self, client, host: str, port: int) -> None:
        super().__init__()
        self.title("(c)hatsystem2620")
        self.geometry("800x600")
        self.client: client = client(host, port,
                                     self.on_new_message,
                                     self.on_delete_request)

        self.current_user: Optional[str] = None
        self.selected_account: Optional[str] = None

        # pagination state for accounts and messages
        self.account_page_size: int = 10
        self.account_offset: int = 0
        self.message_page_size: int = 10
        self.message_offset: int = 0

        # frames for different screens
        self.login_frame: Optional[tk.Frame] = None
        self.signup_frame: Optional[tk.Frame] = None
        self.chat_frame: Optional[tk.Frame] = None

        # defines unique colors for different users
        self.user_color_map = {}

        # local cache for messages
        self.message_cache: List[Dict[str, Any]] = []

        logging.debug("application initialized")
        self._create_login_frame()

    # ---------- login screen -----------
    def _create_login_frame(self) -> None:
        logging.debug("creating login frame")
        frame = tk.Frame(self)
        frame.pack(expand=True, fill="both")

        title_lbl = tk.Label(frame, text="login", font=("arial", 24))
        title_lbl.pack(pady=20)

        user_lbl = tk.Label(frame, text="username:")
        user_lbl.pack()
        self.login_username_entry = tk.Entry(frame)
        self.login_username_entry.bind(
            "<Control-a>",
            lambda x: self.login_username_entry.selection_range(0, "end") or "break",
        )
        self.login_username_entry.pack(pady=5)

        pass_lbl = tk.Label(frame, text="password:")
        pass_lbl.pack()
        self.login_password_entry = tk.Entry(frame, show="*")
        self.login_password_entry.bind(
            "<Control-a>",
            lambda x: self.login_password_entry.selection_range(0, "end") or "break",
        )
        self.login_password_entry.bind("<Return>", lambda _x: self.login())
        self.login_password_entry.pack(pady=5)

        login_btn = tk.Button(frame, text="login", command=self.login)
        login_btn.pack(pady=20)

        switch_btn = tk.Button(frame, text="sign up", command=self._switch_to_signup)
        switch_btn.pack(pady=10)

        self.login_frame = frame
        logging.debug("login frame created")

    def login(self) -> None:
        username = self.login_username_entry.get().strip()
        password = self.login_password_entry.get().strip()
        logging.debug("attempting login for user '%s'", username)
        try:
            unread_count = self.client.login(username, password)
        except Exception as e:
            logging.error("login error for user '%s': %s", username, e)
            messagebox.showerror("login error", str(e))
            return
        self.current_user = username
        messagebox.showinfo("login", f"you have {unread_count} unread messages")
        self.login_frame.destroy()
        self._create_chat_frame()

    # ---------- signup screen -----------
    def _create_signup_frame(self) -> None:
        logging.debug("creating signup frame")
        frame = tk.Frame(self)
        frame.pack(expand=True, fill="both")

        self.password_container = tk.Frame(frame)

        title_lbl = tk.Label(frame, text="create account", font=("arial", 24))
        title_lbl.pack(pady=20)

        user_lbl = tk.Label(frame, text="username:")
        user_lbl.pack()
        self.signup_username_entry = tk.Entry(frame)
        self.signup_username_entry.pack(pady=5)
        self.signup_username_entry.bind(
            "<Control-a>",
            lambda x: self.signup_username_entry.selection_range(0, "end") or "break",
        )
        self.signup_username_entry.bind("<Return>", self.check_username_availability)

        check_btn = tk.Button(frame, text="continue", command=self.check_username_availability)
        check_btn.pack(pady=5)

        self.status_label = tk.Label(frame, text="")
        self.pass_lbl = tk.Label(self.password_container, text="password:")
        self.signup_password_entry = tk.Entry(self.password_container, show="*")
        self.signup_password_entry.bind(
            "<Control-a>",
            lambda x: self.signup_password_entry.selection_range(0, "end") or "break",
        )
        self.signup_password_entry.bind("<Return>", self.signup)
        self.signup_btn = tk.Button(self.password_container, text="sign up", command=self.signup)

        self.signup_frame = frame
        logging.debug("signup frame created")

    def show_password_fields(self):
        self.status_label.config(text="username available! choose a password")
        self.status_label.pack(pady=5)
        self.password_container.pack()
        self.pass_lbl.pack()
        self.signup_password_entry.pack(pady=5)
        self.signup_btn.pack(pady=20)

    def hide_password_fields(self):
        self.password_container.pack_forget()

    def check_username_availability(self, e: Optional[tk.Event] = None) -> None:
        username = self.signup_username_entry.get().strip()
        logging.debug("checking availability for username '%s'", username)
        if not username:
            messagebox.showerror("error", "enter a username")
            return
        try:
            available = not self.client.account_exists(username)
        except Exception as e:
            logging.error("error when checking username availability: %s", e)
            messagebox.showerror("error", str(e))
            return
        if available:
            logging.info("username '%s' is available", username)
            self.status_label.config(
                text="username available. enter a password to create your account.",
                fg="green",
            )
            self.signup_available = True
            self.show_password_fields()
            if hasattr(self, "login_link"):
                self.login_link.pack_forget()
        else:
            logging.warning("username '%s' is already taken", username)
            self.signup_available = False
            self.status_label.config(
                text="username is already taken. pick a different username or",
                fg="red",
            )
            self.status_label.pack(pady=5)
            if not hasattr(self, "login_link"):
                self.login_link = tk.Label(
                    self.signup_frame, text="log in", fg="cyan", cursor="hand2"
                )
                self.login_link.bind("<Button-1>", lambda e: self._switch_to_login())
                self.login_link.pack(pady=5)
            self.hide_password_fields()

    def signup(self, e: Optional[tk.Event] = None) -> None:
        username = self.signup_username_entry.get().strip()
        password = self.signup_password_entry.get().strip()
        logging.debug("attempting signup for username '%s'", username)
        if not getattr(self, "signup_available", False):
            messagebox.showerror("error", "choose a different username")
            return
        if not username or not password:
            messagebox.showerror("error", "enter both username and password")
            return
        try:
            self.client.create_account(username, password)
            logging.info("account '%s' created successfully", username)
            messagebox.showinfo("success", "account created, please login")
        except Exception as e:
            logging.error("signup error for username '%s': %s", username, e)
            messagebox.showerror("signup error", str(e))
            return
        self.signup_frame.destroy()
        self._create_login_frame()

    def _switch_to_signup(self) -> None:
        logging.debug("switching to signup screen")
        self.login_frame.destroy()
        self._create_signup_frame()

    def _switch_to_login(self) -> None:
        logging.debug("switching to login screen")
        self.signup_frame.destroy()
        self._create_login_frame()

    # ---------- main chat screen -----------
    def _create_chat_frame(self) -> None:
        logging.debug("creating main chat frame")
        frame = tk.Frame(self)
        frame.pack(expand=True, fill="both")
        self.chat_frame = frame

        settings_btn = tk.Button(frame, text="settings", command=self.open_settings)
        settings_btn.pack(anchor="ne", padx=5, pady=5)

        paned = tk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paned.pack(expand=True, fill="both")

        accounts_frame = tk.Frame(paned, width=200)
        paned.add(accounts_frame)

        search_lbl = tk.Label(accounts_frame, text="search:")
        search_lbl.pack(anchor="nw", padx=5, pady=(0, 0))
        self.account_search_entry = tk.Entry(accounts_frame)
        self.account_search_entry.pack(fill="x", padx=5, pady=(0, 5))
        self.account_search_entry.bind("<Return>", self.on_account_search)
        self.account_search_entry.bind(
            "<Control-a>",
            lambda x: self.account_search_entry.selection_range(0, "end") or "break",
        )

        self.accounts_listbox = tk.Listbox(accounts_frame)
        self.accounts_listbox.pack(expand=True, fill="both", padx=5)
        self.accounts_listbox.bind("<<ListboxSelect>>", self.on_account_select)

        acct_pag_frame = tk.Frame(accounts_frame)
        acct_pag_frame.pack(fill="x", padx=5, pady=5)
        prev_acct_btn = tk.Button(acct_pag_frame, text="prev", command=self.prev_accounts_page)
        prev_acct_btn.pack(side="left", expand=True, fill="x")
        next_acct_btn = tk.Button(acct_pag_frame, text="next", command=self.next_accounts_page)
        next_acct_btn.pack(side="left", expand=True, fill="x")

        # right column: messages area using a scrollable canvas and a frame container
        messages_frame = tk.Frame(paned)
        paned.add(messages_frame)

        self.messages_canvas = tk.Canvas(messages_frame)
        self.messages_canvas.pack(side="left", fill="both", expand=True)

        self.messages_scroll = tk.Scrollbar(
            messages_frame, orient="vertical", command=self.messages_canvas.yview
        )
        self.messages_scroll.pack(side="right", fill="y")
        self.messages_canvas.configure(yscrollcommand=self.messages_scroll.set)

        self.messages_container = tk.Frame(self.messages_canvas)
        self.messages_container.bind(
            "<Configure>",
            lambda e: self.messages_canvas.configure(
                scrollregion=self.messages_canvas.bbox("all")
            ),
        )
        self.messages_canvas.create_window((0, 0), window=self.messages_container, anchor="nw")

        # pagination controls for messages
        msg_pag_frame = tk.Frame(frame)
        msg_pag_frame.pack(fill="x", padx=5, pady=5)
        prev_msg_btn = tk.Button(msg_pag_frame, text="prev", command=self.prev_messages_page)
        prev_msg_btn.pack(side="left", expand=True, fill="x")
        next_msg_btn = tk.Button(msg_pag_frame, text="next", command=self.next_messages_page)
        next_msg_btn.pack(side="left", expand=True, fill="x")

        # message input area at the bottom
        input_frame = tk.Frame(frame)
        input_frame.pack(fill="x", padx=5, pady=5)

        to_label = tk.Label(input_frame, text="To:", fg="gray40")
        to_label.pack(side="left", padx=(5, 2))

        self.selected_user_label = tk.Label(input_frame, text="No receiver selected", fg="red")
        self.selected_user_label.pack(side="left", padx=(0, 5))

        self.message_entry = tk.Entry(input_frame)
        self.message_entry.pack(side="left", expand=True, fill="x", padx=5)
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind(
            "<Control-a>",
            lambda x: self.message_entry.selection_range(0, "end") or "break",
        )
        send_btn = tk.Button(input_frame, text="send", command=self.send_message)
        send_btn.pack(side="left", padx=5)

        logging.debug("main chat frame created; loading accounts and messages")
        self.update_accounts_list()
        try:
            # initial full fetch to cache messages (read unread)
            unread_messages = self.client.read_messages(0, 100)

            # merge unread messages with existing cache
            merged_messages = {m['id']: m for m in unread_messages}
            merged_messages.update({m['id']: m for m in self.message_cache})

            # update the message cache with merged messages
            self.message_cache = list(merged_messages.values())
        except Exception as e:
            logging.error("failed to load initial messages: %s", e)
            messagebox.showerror("error", f"failed to load messages: {e}")
            self.message_cache = []
        self.update_messages_area()

    def on_account_search(self, event: tk.Event) -> None:
        logging.debug("account search triggered")
        self.account_offset = 0
        query = self.account_search_entry.get().strip()
        if not query:
            query = "*"
        self.update_accounts_list(query)

    def update_accounts_list(self, pattern: str = "*") -> None:
        logging.debug("updating accounts list with pattern '%s'", pattern)
        try:
            accounts = self.client.list_accounts(
                pattern, self.account_offset, self.account_page_size
            )
        except Exception as e:
            logging.error("failed to load accounts: %s", e)
            messagebox.showerror("error", f"failed to load accounts: {e}")
            return
        self.accounts_listbox.delete(0, tk.END)
        for acct in accounts:
            self.accounts_listbox.insert(tk.END, acct)

    def prev_accounts_page(self) -> None:
        if self.account_offset >= self.account_page_size:
            self.account_offset -= self.account_page_size
            query = self.account_search_entry.get().strip() or "*"
            logging.debug("navigating to previous accounts page, new offset %d", self.account_offset)
            self.update_accounts_list(query)

    def next_accounts_page(self) -> None:
        self.account_offset += self.account_page_size
        query = self.account_search_entry.get().strip() or "*"
        logging.debug("navigating to next accounts page, new offset %d", self.account_offset)
        self.update_accounts_list(query)

    def on_account_select(self, event: tk.Event) -> None:
        selection = self.accounts_listbox.curselection()
        if selection:
            self.selected_account = self.accounts_listbox.get(selection[0])
            logging.debug("selected conversation with account: %s", self.selected_account)
            color = self.get_user_color(self.selected_account)
            self.selected_user_label.config(text=self.selected_account, fg=color)
            self.message_offset = 0
            # initial full fetch to cache messages (read unread)
            unread_messages = self.client.read_messages(0, 100)

            # merge unread messages with existing cache
            merged_messages = {m['id']: m for m in unread_messages}
            merged_messages.update({m['id']: m for m in self.message_cache})

            # update the message cache with merged messages
            self.message_cache = list(merged_messages.values())
            self.update_messages_area()
        else:
            self.selected_account = None

    def update_messages_area(self) -> None:
        for widget in self.messages_container.winfo_children():
            widget.destroy()
        if self.selected_account:
            filtered = [
                msg for msg in self.message_cache
                if msg.get("from") == self.selected_account or msg.get("to") == self.selected_account
            ]
            messages = filtered[self.message_offset:self.message_offset + self.message_page_size]
        else:
            messages = self.message_cache[self.message_offset:self.message_offset + self.message_page_size]
        for msg in messages:
            color = self.get_user_color(msg.get("from", "unknown"))
            ml = message_line(self.messages_container, msg, self.delete_message, user_color=color)
            ml.pack(fill="x", pady=2, padx=2)
        self.messages_container.update_idletasks()
        self.messages_canvas.configure(
            scrollregion=self.messages_canvas.bbox("all")
        )
        logging.debug(
            "messages area updated; offset %d, count %d",
            self.message_offset,
            self.message_page_size,
        )

    def on_new_message(self, msg) -> None:
        # append new message to the cache if not already present
        if not any(m["id"] == msg["id"] for m in self.message_cache):
            self.message_cache.append(msg)
            self.update_messages_area()

    def on_delete_request(self, data) -> None:
        # remove messages with matching ids from cache
        logging.debug("Cache before: %s", str(self.message_cache))
        self.message_cache = [m for m in self.message_cache if m["id"] not in data.get("ids", [])]
        logging.debug("Cache after: %s", str(self.message_cache))
        self.update_messages_area()

    def prev_messages_page(self) -> None:
        if self.message_offset >= self.message_page_size:
            self.message_offset -= self.message_page_size
            logging.debug("navigating to previous messages page, new offset %d", self.message_offset)
            self
            self.update_messages_area()

    def next_messages_page(self) -> None:
        self.message_offset += self.message_page_size
        logging.debug("navigating to next messages page, new offset %d", self.message_offset)
        self.update_messages_area()

    def send_message(self, event: Optional[tk.Event] = None) -> None:
        content = self.message_entry.get().strip()
        logging.debug("attempting to send message: %s", content)
        if not self.selected_account:
            logging.error("no recipient selected when trying to send message")
            messagebox.showerror("error", "no recipient selected")
            return
        if not content:
            return
        try:
            new_id = self.client.send_message(self.selected_account, content)
            logging.info("message sent to '%s'", self.selected_account)
            new_msg = {
                "id": new_id,
                "from": self.current_user,
                "to": self.selected_account,
                "timestamp": int(datetime.now().strftime("%s")),
                "content": content,
            }
            if not any(m["id"] == new_msg["id"] for m in self.message_cache):
                self.message_cache.append(new_msg)
        except Exception as e:
            logging.error("failed to send message: %s", e)
            messagebox.showerror("error", f"failed to send message: {e}")
            return
        self.message_entry.delete(0, tk.END)
        self.update_messages_area()

    def delete_message(self, message_id: int) -> None:
        logging.info("attempting to delete message with id %d", message_id)
        try:
            self.client.delete_message(message_id)
            self.message_cache = [msg for msg in self.message_cache if msg["id"] != message_id]
        except Exception as e:
            logging.error("failed to delete message: %s", e)
            messagebox.showerror("error", f"failed to delete message: {e}")
            return
        self.update_messages_area()

    def open_settings(self) -> None:
        logging.debug("opening settings window")
        settings_win = tk.Toplevel(self)
        settings_win.title("settings")
        settings_win.geometry("300x200")

        lbl = tk.Label(settings_win, text="messages per page:")
        lbl.pack(pady=10)
        per_page_entry = tk.Entry(settings_win)
        per_page_entry.insert(0, str(self.message_page_size))
        per_page_entry.pack(pady=5)

        delete_btn = tk.Button(
            settings_win, text="delete account", command=self.delete_account
        )
        delete_btn.pack(pady=5)

        def save_settings() -> None:
            try:
                new_val = int(per_page_entry.get().strip())
                if new_val <= 0:
                    raise ValueError
                self.message_page_size = new_val
                settings_win.destroy()
                self.message_offset = 0
                self.update_messages_area()
                logging.info("settings updated: message_page_size set to %d", new_val)
            except ValueError:
                logging.error("invalid value entered for messages per page")
                messagebox.showerror("error", "enter a valid positive number")

        save_btn = tk.Button(settings_win, text="save", command=save_settings)
        save_btn.pack(pady=10)

    def delete_account(self) -> None:
        logging.info("deleting account '%s'", self.current_user)
        try:
            self.client.delete_account(self.current_user)
        except Exception as e:
            logging.error("failed to delete account: %s", e)
            messagebox.showerror("error", f"failed to delete account: {e}")
            return
        messagebox.showinfo("account deleted", "your account has been deleted")
        self.chat_frame.destroy()
        self._create_login_frame()

    def get_user_color(self, username: str) -> str:
        if username not in self.user_color_map:
            idx = len(self.user_color_map) % len(USER_COLORS)
            self.user_color_map[username] = USER_COLORS[idx]
        return self.user_color_map[username]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="irc/gmail hybrid chat application"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose logging (default shows errors only)",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.ERROR
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.info("starting chat application")
    app = chatapp(JSONClient, "localhost", 12345)
    app.mainloop()
    logging.info("chat application closed")

