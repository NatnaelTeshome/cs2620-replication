import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
import argparse

# dummy client for illustration purposes
class client:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.session_token = None
        self.username: Optional[str] = None
        # dummy storage for testing
        self.accounts = {"alice": "password", "bob": "abc", "natnael": "teshome", "michal": "kurek"}
        self.messages = [
            {"id": 1, "from": "alice", "to": "michal", "timestamp": 1739064990, "content": "hey"},
            {"id": 2, "from": "bob", "to": "michal", "timestamp": 1739065050, "content": "hello"},
            {"id": 3, "from": "alice", "to": "michal", "timestamp": 1739065110, "content": "how r u?"},
            {"id": 4, "from": "michal", "to": "alice", "timestamp": 1739065170, "content": "i'm good, u?"},
            {"id": 5, "from": "alice", "to": "michal", "timestamp": 1739065230, "content": "doing alright"},
            {"id": 6, "from": "bob", "to": "alice", "timestamp": 1739065290, "content": "nice to hear"},
            {"id": 7, "from": "michal", "to": "bob", "timestamp": 1739065350, "content": "what's up?"},
            {"id": 8, "from": "bob", "to": "michal", "timestamp": 1739065410, "content": "not much, just chilling"},
            {"id": 9, "from": "alice", "to": "bob", "timestamp": 1739065470, "content": "same here"},
            {"id": 10, "from": "michal", "to": "alice", "timestamp": 1739065530, "content": "wanna hang out later?"}
        ]
        logging.debug("client initialized with host '%s' and port '%s'",
                      host, port)

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
        if pattern != "*" and pattern:
            accounts = [acct for acct in accounts if pattern in acct]
        result = accounts[offset: offset + limit]
        logging.debug("list_accounts with pattern '%s', offset %d, limit %d: %s",
                      pattern, offset, limit, result)
        return result

    def read_messages(self, offset: int = 0, count: int = 10, to_user: Optional[str] = None) -> List[Dict[str, Any]]:
        if to_user:
            result = [
                msg for msg in self.messages
                if (msg["to"] == self.username and msg["from"] == to_user) or
                (msg["from"] == self.username and msg["to"] == to_user)
            ]
        else:
            result = [
                msg for msg in self.messages
                if msg["to"] == self.username or msg["from"] == self.username
            ]
        result = result[offset: offset + count]
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


class chatapp(tk.Tk):
    def __init__(self, host: str, port: int) -> None:
        super().__init__()
        self.title("(C)hat(S)ystem2620")
        self.geometry("800x600")
        self.client: client = client(host, port)
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
            '<Control-a>',
            lambda x: self.login_username_entry.selection_range(0, 'end') or "break"
        )
        self.login_username_entry.pack(pady=5)

        pass_lbl = tk.Label(frame, text="password:")
        pass_lbl.pack()
        self.login_password_entry = tk.Entry(frame, show="*")
        self.login_password_entry.bind(
            '<Control-a>',
            lambda x: self.login_password_entry.selection_range(0, 'end') or "break"
        )
        self.login_password_entry.bind('<Return>', lambda _x: self.login())
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

        title_lbl = tk.Label(frame, text="create account", font=("arial", 24))
        title_lbl.pack(pady=20)

        user_lbl = tk.Label(frame, text="username:")
        user_lbl.pack()
        self.signup_username_entry = tk.Entry(frame)
        self.signup_username_entry.pack(pady=5)
        self.signup_username_entry.bind(
            '<Control-a>',
            lambda x: self.signup_username_entry.selection_range(0, 'end') or "break"
        )

        check_btn = tk.Button(frame, text="check availability", command=self.check_username_availability)
        check_btn.pack(pady=5)

        pass_lbl = tk.Label(frame, text="password:")
        pass_lbl.pack()
        self.signup_password_entry = tk.Entry(frame, show="*")
        self.signup_password_entry.pack(pady=5)
        self.signup_password_entry.bind(
            '<Control-a>',
            lambda x: self.signup_password_entry.selection_range(0, 'end') or "break"
        )

        signup_btn = tk.Button(frame, text="sign up", command=self.signup)
        signup_btn.pack(pady=20)

        switch_btn = tk.Button(frame, text="already have an account? login", command=self._switch_to_login)
        switch_btn.pack(pady=10)

        self.signup_frame = frame
        logging.debug("signup frame created")

    def check_username_availability(self) -> None:
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
            messagebox.showinfo("available", "username is available")
            logging.info("username '%s' is available", username)
            self.signup_available = True
        else:
            messagebox.showerror("username taken", "account already exists")
            logging.warning("username '%s' is already taken", username)
            self.signup_available = False

    def signup(self) -> None:
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

        # settings button (top right)
        settings_btn = tk.Button(frame, text="settings", command=self.open_settings)
        settings_btn.pack(anchor="ne", padx=5, pady=5)

        # paned window dividing the accounts column and the messages area
        paned = tk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paned.pack(expand=True, fill="both")

        # left column: accounts column with search functionality
        accounts_frame = tk.Frame(paned, width=200)
        paned.add(accounts_frame)

        search_lbl = tk.Label(accounts_frame, text="search:")
        search_lbl.pack(anchor="nw", padx=5, pady=(5, 0))
        self.account_search_entry = tk.Entry(accounts_frame)
        self.account_search_entry.pack(fill="x", padx=5, pady=(0, 5))
        self.account_search_entry.bind("<Return>", self.on_account_search)
        self.account_search_entry.bind(
            '<Control-a>',
            lambda x: self.account_search_entry.selection_range(0, 'end') or "break"
        )

        self.accounts_listbox = tk.Listbox(accounts_frame)
        self.accounts_listbox.pack(expand=True, fill="both", padx=5)
        self.accounts_listbox.bind("<<ListboxSelect>>", self.on_account_select)

        # pagination controls for accounts list
        acct_pag_frame = tk.Frame(accounts_frame)
        acct_pag_frame.pack(fill="x", padx=5, pady=5)
        prev_acct_btn = tk.Button(acct_pag_frame, text="prev", command=self.prev_accounts_page)
        prev_acct_btn.pack(side="left", expand=True, fill="x")
        next_acct_btn = tk.Button(acct_pag_frame, text="next", command=self.next_accounts_page)
        next_acct_btn.pack(side="left", expand=True, fill="x")

        # right column: messages area and message input
        messages_frame = tk.Frame(paned)
        paned.add(messages_frame)

        self.messages_text = tk.Text(messages_frame, state="disabled", wrap="word")
        self.messages_text.pack(expand=True, fill="both", padx=5, pady=5)
        msg_scroll = tk.Scrollbar(messages_frame, command=self.messages_text.yview)
        msg_scroll.pack(side="right", fill="y")
        self.messages_text.config(yscrollcommand=msg_scroll.set)

        # pagination controls for messages
        msg_pag_frame = tk.Frame(messages_frame)
        msg_pag_frame.pack(fill="x", padx=5, pady=5)
        prev_msg_btn = tk.Button(msg_pag_frame, text="prev", command=self.prev_messages_page)
        prev_msg_btn.pack(side="left", expand=True, fill="x")
        next_msg_btn = tk.Button(msg_pag_frame, text="next", command=self.next_messages_page)
        next_msg_btn.pack(side="left", expand=True, fill="x")

        # message input area at the bottom of messages area
        input_frame = tk.Frame(messages_frame)
        input_frame.pack(fill="x", padx=5, pady=5)
        self.message_entry = tk.Entry(input_frame)
        self.message_entry.pack(side="left", expand=True, fill="x", padx=5)
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind(
            '<Control-a>',
            lambda x: self.message_entry.selection_range(0, 'end') or "break"
        )
        send_btn = tk.Button(input_frame, text="send", command=self.send_message)
        send_btn.pack(side="left", padx=5)

        logging.debug("main chat frame created; loading accounts and messages")
        self.update_accounts_list()
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
            accounts = self.client.list_accounts(pattern,
                                                 self.account_offset,
                                                 self.account_page_size)
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
            self.update_messages_area()
        # else:
            # self.selected_account = None
            # logging.debug("no account selected; showing all messages")
        self.message_offset = 0

    def update_messages_area(self) -> None:
        try:
            messages = self.client.read_messages(self.message_offset, self.message_page_size)
        except Exception as e:
            logging.error("failed to fetch messages: %s", e)
            messagebox.showerror("error", f"failed to fetch messages: {e}")
            return

        # filter messages if a conversation is selected
        if self.selected_account:
            assert(self.current_user)
            filtered = []
            for msg in messages:
                # only show messages between current user and selected account
                assert("from" in msg and "to" in msg)
                if self.selected_account == msg["from"] or self.selected_account == msg["to"]:
                    filtered.append(msg)
            messages = filtered

        self.messages_text.config(state="normal")
        self.messages_text.delete("1.0", tk.END)
        for msg in messages:
            sender = msg.get("from", "unknown")
            timestamp = datetime.fromtimestamp(msg.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
            content = msg.get("content", "")
            tag = sender  # use from as a text tag for color coding
            if tag not in self.messages_text.tag_names():
                colors = {"alice": "blue", "bob": "green", "me": "purple"}
                color = colors.get(sender, "black")
                self.messages_text.tag_config(tag, foreground=color)
            self.messages_text.insert(tk.END, f"[{timestamp}] {sender}: {content}\n", tag)
        self.messages_text.config(state="disabled")
        logging.debug("messages area updated; offset %d, count %d",
                      self.message_offset, self.message_page_size)

    def prev_messages_page(self) -> None:
        if self.message_offset >= self.message_page_size:
            self.message_offset -= self.message_page_size
            logging.debug("navigating to previous messages page, new offset %d", self.message_offset)
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
            self.client.send_message(self.selected_account, content)
            logging.info("message sent to '%s'", self.selected_account)
        except Exception as e:
            logging.error("failed to send message: %s", e)
            messagebox.showerror("error", f"failed to send message: {e}")
            return
        self.message_entry.delete(0, tk.END)
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
            settings_win,
            text="delete account",
            command=self.delete_account
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
        # return to login screen, destroying chat frame
        self.chat_frame.destroy()
        self._create_login_frame()

    def open_settings_backup(self) -> None:
        # TODO: Remove this legacy code
        logging.debug("opening settings window")
        settings_win = tk.Toplevel(self)
        settings_win.title("settings")
        settings_win.geometry("300x250")

        # messages per page setting
        lbl = tk.Label(settings_win, text="messages per page:")
        lbl.pack(pady=10)
        per_page_entry = tk.Entry(settings_win)
        per_page_entry.insert(0, str(self.message_page_size))
        per_page_entry.pack(pady=5)

        # theme selection section
        style_lbl = tk.Label(settings_win, text="select theme:")
        style_lbl.pack(pady=10)
        style = ttk.Style()
        available_themes = style.theme_names()  # list available themes
        theme_var = tk.StringVar(settings_win)
        theme_var.set(style.theme_use())  # current theme

        theme_menu = tk.OptionMenu(settings_win, theme_var, *available_themes)
        theme_menu.pack(pady=5)

        def apply_theme() -> None:
            selected_theme = theme_var.get()
            style.theme_use(selected_theme)
            logging.info("theme applied: %s", selected_theme)
            messagebox.showinfo("theme applied", f"applied theme: {selected_theme}")

        apply_theme_btn = tk.Button(settings_win, text="apply theme", command=apply_theme)
        apply_theme_btn.pack(pady=5)

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="irc/gmail hybrid chat application"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="enable verbose logging (default shows errors only)"
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.ERROR
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logging.info("starting chat application")
    app = chatapp("localhost", 12345)
    app.mainloop()
    logging.info("chat application closed")



