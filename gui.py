import tkinter as tk
from tkinter import messagebox
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime
import logging
import argparse

from client_grpc import CustomProtocolClient

USER_COLORS: List[str] = [
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


# custom message line widget: shows a message and, on hover, an inline "delete" link
class message_line(tk.Frame):
    def __init__(
        self,
        parent: tk.Widget,
        msg_data: Dict[str, Any],
        delete_callback: Callable[[int], None],
        user_color: str = "gray40",
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(parent, *args, **kwargs)
        self.msg_data: Dict[str, Any] = msg_data
        self.delete_callback: Callable[[int], None] = delete_callback

        # Get timestamp, sender and content from msg_data.
        timestamp: str = datetime.fromtimestamp(msg_data.get("timestamp", 0)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        sender: str = msg_data.get("from_", "unknown")
        content: str = msg_data.get("content", "[ERROR] No message content")
        message_text: str = f"[{timestamp}] {sender}: {content}"

        self.text_label: tk.Label = tk.Label(
            self, text=message_text, anchor="w", fg=user_color
        )
        self.text_label.grid(row=0, column=0, sticky="w")

        self.delete_label: tk.Label = tk.Label(
            self, text="delete", fg="red", cursor="hand2"
        )
        self.delete_label.grid(row=0, column=1, sticky="e", padx=(10, 0))
        self.delete_label.grid_remove()

        # bind events to self and its child labels
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.text_label.bind("<Enter>", self.on_enter)
        self.text_label.bind("<Leave>", self.on_leave)
        self.delete_label.bind("<Enter>", self.on_enter)
        self.delete_label.bind("<Leave>", self.on_leave)
        self.delete_label.bind("<Button-1>", lambda e: self.on_delete())

        self.hide_job: Optional[str] = None  # Job id returned by self.after()

    def on_enter(self, event: Optional[tk.Event] = None) -> None:
        if self.hide_job is not None:
            self.after_cancel(self.hide_job)
            self.hide_job = None
        self.delete_label.grid()

    def on_leave(self, event: Optional[tk.Event] = None) -> None:
        self.hide_job = self.after(50, self.hide_delete)

    def hide_delete(self) -> None:
        self.delete_label.grid_remove()
        self.hide_job = None

    def on_delete(self) -> None:
        # Call the provided callback with the message id.
        self.delete_callback(self.msg_data["id"])


class chatapp(tk.Tk):
    def __init__(
        self,
        client_class: Callable[
            [
                str,
                int,
                Callable[[Dict[str, Any]], None],
                Callable[[Dict[str, Any]], None],
            ],
            CustomProtocolClient,
        ],
        host: str,
        port: int,
    ) -> None:
        super().__init__()
        self.title("(c)hatsystem2620")
        self.geometry("800x600")
        self.proto_client: CustomProtocolClient = client_class(
            host, port, self.on_new_message, self.on_delete_request
        )

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
        self.user_color_map: Dict[str, str] = {}

        # local cache for messages
        self.message_cache: List[Dict[str, Any]] = []

        # Link back to the login frame
        self.login_link: Optional[tk.Label] = None

        logging.debug("application initialized")
        self._create_login_frame()

    def _select_all(self, _event: tk.Event) -> str:
        self.login_username_entry.selection_range(0, "end")
        return "break"

    # ---------- login screen -----------
    def _create_login_frame(self) -> None:
        logging.debug("creating login frame")
        frame: tk.Frame = tk.Frame(self)
        frame.pack(expand=True, fill="both")

        title_lbl: tk.Label = tk.Label(frame, text="login", font=("arial", 24))
        title_lbl.pack(pady=20)

        user_lbl: tk.Label = tk.Label(frame, text="username:")
        user_lbl.pack()
        self.login_username_entry: tk.Entry = tk.Entry(frame)
        self.login_username_entry.bind("<Control-a>", self._select_all)
        self.login_username_entry.pack(pady=5)

        pass_lbl: tk.Label = tk.Label(frame, text="password:")
        pass_lbl.pack()
        self.login_password_entry: tk.Entry = tk.Entry(frame, show="*")
        self.login_password_entry.bind("<Control-a>", self._select_all)
        self.login_password_entry.bind("<Return>", lambda _x: self.login())
        self.login_password_entry.pack(pady=5)

        login_btn: tk.Button = tk.Button(frame, text="login", command=self.login)
        login_btn.pack(pady=20)

        switch_btn: tk.Button = tk.Button(
            frame, text="sign up", command=self._switch_to_signup
        )
        switch_btn.pack(pady=10)

        self.login_frame = frame
        logging.debug("login frame created")

    def login(self) -> None:
        username: str = self.login_username_entry.get().strip()
        password: str = self.login_password_entry.get().strip()
        logging.debug("attempting login for user '%s'", username)
        try:
            unread_msg: str = self.proto_client.login(username, password)
        except Exception as e:
            logging.error("login error for user '%s': %s", username, e)
            messagebox.showerror("login error", str(e))
            return
        self.current_user = username
        messagebox.showinfo("login", f"you have {unread_msg} unread messages")
        if self.login_frame:
            self.login_frame.destroy()
        self._create_chat_frame()

    # ---------- signup screen -----------
    def _create_signup_frame(self) -> None:
        logging.debug("creating signup frame")
        frame: tk.Frame = tk.Frame(self)
        frame.pack(expand=True, fill="both")

        self.password_container: tk.Frame = tk.Frame(frame)

        title_lbl: tk.Label = tk.Label(frame, text="create account", font=("arial", 24))
        title_lbl.pack(pady=20)

        user_lbl: tk.Label = tk.Label(frame, text="username:")
        user_lbl.pack()
        self.signup_username_entry: tk.Entry = tk.Entry(frame)
        self.signup_username_entry.pack(pady=5)
        self.signup_username_entry.bind("<Control-a>", self._select_all)
        self.signup_username_entry.bind("<Return>", self.check_username_availability)

        check_btn: tk.Button = tk.Button(
            frame, text="continue", command=self.check_username_availability
        )
        check_btn.pack(pady=5)

        self.status_label: tk.Label = tk.Label(frame, text="")
        self.pass_lbl: tk.Label = tk.Label(self.password_container, text="password:")
        self.signup_password_entry: tk.Entry = tk.Entry(
            self.password_container, show="*"
        )
        self.signup_password_entry.bind("<Control-a>", self._select_all)
        self.signup_password_entry.bind("<Return>", self.signup)
        self.signup_btn: tk.Button = tk.Button(
            self.password_container, text="sign up", command=self.signup
        )

        self.signup_frame = frame
        logging.debug("signup frame created")

    def show_password_fields(self) -> None:
        self.status_label.config(text="username available! choose a password")
        self.status_label.pack(pady=5)
        self.password_container.pack()
        self.pass_lbl.pack()
        self.signup_password_entry.pack(pady=5)
        self.signup_btn.pack(pady=20)

    def hide_password_fields(self) -> None:
        self.password_container.pack_forget()

    def check_username_availability(self, e: Optional[tk.Event] = None) -> None:
        username: str = self.signup_username_entry.get().strip()
        logging.debug("checking availability for username '%s'", username)
        if not username:
            messagebox.showerror("error", "enter a username")
            return
        try:
            available: bool = not self.proto_client.account_exists(username)
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
            # This attribute is set dynamically.
            self.signup_available = True
            self.show_password_fields()
            if self.login_link:
                self.login_link.pack_forget()
        else:
            logging.warning("username '%s' is already taken", username)
            self.signup_available = False
            self.status_label.config(
                text="username is already taken. pick a different username or",
                fg="red",
            )
            self.status_label.pack(pady=5)
            if self.login_link is None:
                self.login_link = tk.Label(
                    self.signup_frame, text="log in", fg="cyan", cursor="hand2"
                )
                self.login_link.bind("<Button-1>", lambda e: self._switch_to_login())
                self.login_link.pack(pady=5)
            self.hide_password_fields()

    def signup(self, e: Optional[tk.Event] = None) -> None:
        username: str = self.signup_username_entry.get().strip()
        password: str = self.signup_password_entry.get().strip()
        logging.debug("attempting signup for username '%s'", username)
        if not getattr(self, "signup_available", False):
            messagebox.showerror("error", "choose a different username")
            return
        if not username or not password:
            messagebox.showerror("error", "enter both username and password")
            return
        try:
            self.proto_client.create_account(username, password)
            logging.info("account '%s' created successfully", username)
            messagebox.showinfo("success", "account created, please login")
        except Exception as e:
            logging.error("signup error for username '%s': %s", username, e)
            messagebox.showerror("signup error", str(e))
            return
        if self.signup_frame:
            self.signup_frame.destroy()
        self._create_login_frame()

    def _switch_to_signup(self) -> None:
        logging.debug("switching to signup screen")
        if self.login_frame:
            self.login_frame.destroy()
        self._create_signup_frame()

    def _switch_to_login(self) -> None:
        logging.debug("switching to login screen")
        if self.signup_frame:
            self.signup_frame.destroy()
        self._create_login_frame()

    # ---------- main chat screen -----------
    def _create_chat_frame(self) -> None:
        logging.debug("creating main chat frame")
        frame: tk.Frame = tk.Frame(self)
        frame.pack(expand=True, fill="both")
        self.chat_frame = frame

        settings_btn: tk.Button = tk.Button(
            frame, text="settings", command=self.open_settings
        )
        settings_btn.pack(anchor="ne", padx=5, pady=5)

        paned: tk.PanedWindow = tk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paned.pack(expand=True, fill="both")

        accounts_frame: tk.Frame = tk.Frame(paned, width=200)
        paned.add(accounts_frame)

        search_lbl: tk.Label = tk.Label(accounts_frame, text="search:")
        search_lbl.pack(anchor="nw", padx=5, pady=(0, 0))
        self.account_search_entry: tk.Entry = tk.Entry(accounts_frame)
        self.account_search_entry.pack(fill="x", padx=5, pady=(0, 5))
        self.account_search_entry.bind("<Return>", self.on_account_search)
        self.account_search_entry.bind("<Control-a>", self._select_all)

        self.accounts_listbox: tk.Listbox = tk.Listbox(accounts_frame)
        self.accounts_listbox.pack(expand=True, fill="both", padx=5)
        self.accounts_listbox.bind("<<ListboxSelect>>", self.on_account_select)

        acct_pag_frame: tk.Frame = tk.Frame(accounts_frame)
        acct_pag_frame.pack(fill="x", padx=5, pady=5)
        prev_acct_btn: tk.Button = tk.Button(
            acct_pag_frame, text="prev", command=self.prev_accounts_page
        )
        prev_acct_btn.pack(side="left", expand=True, fill="x")
        next_acct_btn: tk.Button = tk.Button(
            acct_pag_frame, text="next", command=self.next_accounts_page
        )
        next_acct_btn.pack(side="left", expand=True, fill="x")

        # right column: messages area using a scrollable canvas and a frame container
        messages_frame: tk.Frame = tk.Frame(paned)
        paned.add(messages_frame)

        self.messages_canvas: tk.Canvas = tk.Canvas(messages_frame)
        self.messages_canvas.pack(side="left", fill="both", expand=True)

        self.messages_scroll: tk.Scrollbar = tk.Scrollbar(
            messages_frame, orient="vertical", command=self.messages_canvas.yview
        )
        self.messages_scroll.pack(side="right", fill="y")
        self.messages_canvas.configure(yscrollcommand=self.messages_scroll.set)

        self.messages_container: tk.Frame = tk.Frame(self.messages_canvas)
        self.messages_container.bind(
            "<Configure>",
            lambda e: self.messages_canvas.configure(
                scrollregion=self.messages_canvas.bbox("all")
            ),
        )
        self.messages_canvas.create_window(
            (0, 0), window=self.messages_container, anchor="nw"
        )

        # pagination controls for messages
        msg_pag_frame: tk.Frame = tk.Frame(frame)
        msg_pag_frame.pack(fill="x", padx=5, pady=5)
        prev_msg_btn: tk.Button = tk.Button(
            msg_pag_frame, text="prev", command=self.prev_messages_page
        )
        prev_msg_btn.pack(side="left", expand=True, fill="x")
        next_msg_btn: tk.Button = tk.Button(
            msg_pag_frame, text="next", command=self.next_messages_page
        )
        next_msg_btn.pack(side="left", expand=True, fill="x")

        # message input area at the bottom
        input_frame: tk.Frame = tk.Frame(frame)
        input_frame.pack(fill="x", padx=5, pady=5)

        to_label: tk.Label = tk.Label(input_frame, text="To:", fg="gray40")
        to_label.pack(side="left", padx=(5, 2))

        self.selected_user_label: tk.Label = tk.Label(
            input_frame, text="No receiver selected", fg="red"
        )
        self.selected_user_label.pack(side="left", padx=(0, 5))

        self.message_entry: tk.Entry = tk.Entry(input_frame)
        self.message_entry.pack(side="left", expand=True, fill="x", padx=5)
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<Control-a>", self._select_all)
        send_btn: tk.Button = tk.Button(
            input_frame, text="send", command=self.send_message
        )
        send_btn.pack(side="left", padx=5)

        logging.debug("main chat frame created; loading accounts and messages")
        self.update_accounts_list()
        try:
            # initial full fetch to cache messages (read unread)
            unread_messages: List[Dict[str, Any]] = self.proto_client.read_messages(
                0, 100
            )

            # merge unread messages with existing cache
            merged_messages: Dict[int, Dict[str, Any]] = {
                m["id"]: m for m in unread_messages
            }
            merged_messages.update({m["id"]: m for m in self.message_cache})

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
        query: str = self.account_search_entry.get().strip()
        if not query:
            query = "*"
        self.update_accounts_list(query)

    def update_accounts_list(self, pattern: str = "*") -> None:
        logging.debug("updating accounts list with pattern '%s'", pattern)
        try:
            accounts: List[str] = self.proto_client.list_accounts(
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
            query: str = self.account_search_entry.get().strip() or "*"
            logging.debug(
                "navigating to previous accounts page, new offset %d",
                self.account_offset,
            )
            self.update_accounts_list(query)

    def next_accounts_page(self) -> None:
        self.account_offset += self.account_page_size
        query: str = self.account_search_entry.get().strip() or "*"
        logging.debug(
            "navigating to next accounts page, new offset %d", self.account_offset
        )
        self.update_accounts_list(query)

    def on_account_select(self, event: tk.Event) -> None:
        selection = self.accounts_listbox.curselection()
        if selection:
            self.selected_account = self.accounts_listbox.get(selection[0])
            logging.debug(
                "selected conversation with account: %s", self.selected_account
            )
            color: str = self.get_user_color(self.selected_account)
            self.selected_user_label.config(text=str(self.selected_account), fg=color)
            self.message_offset = 0
            # initial full fetch to cache messages (read unread)
            unread_messages: List[Dict[str, Any]] = self.proto_client.read_messages(
                0, 100
            )

            merged_messages: Dict[int, Dict[str, Any]] = {
                m["id"]: m for m in unread_messages
            }
            merged_messages.update({m["id"]: m for m in self.message_cache})
            self.message_cache = list(merged_messages.values())
            self.update_messages_area()
        else:
            self.selected_account = None

    def update_messages_area(self) -> None:
        for widget in self.messages_container.winfo_children():
            widget.destroy()
        if self.selected_account:
            filtered: List[Dict[str, Any]] = [
                msg
                for msg in self.message_cache
                if msg.get("from_", "") == self.selected_account
                or msg.get("to", "") == self.selected_account
            ]
            messages: List[Dict[str, Any]] = filtered[
                self.message_offset : self.message_offset + self.message_page_size
            ]
        else:
            messages = self.message_cache[
                self.message_offset : self.message_offset + self.message_page_size
            ]
        for msg in messages:
            color: str = self.get_user_color(msg.get("from_", "unknown"))
            ml: message_line = message_line(
                self.messages_container, msg, self.delete_message, user_color=color
            )
            ml.pack(fill="x", pady=2, padx=2)
        self.messages_container.update_idletasks()
        self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))
        logging.debug(
            "messages area updated; offset %d, count %d",
            self.message_offset,
            self.message_page_size,
        )

    def on_new_message(self, msg: Dict[str, Any]) -> None:
        # Append new message to the cache if not already present.
        if not any(m["id"] == msg["id"] for m in self.message_cache):
            self.message_cache.append(msg)
            self.update_messages_area()

    def on_delete_request(self, data: Dict[str, Any]) -> None:
        # Remove messages with matching ids from cache.
        logging.debug("Cache before: %s", str(self.message_cache))
        self.message_cache = [
            m for m in self.message_cache if m["id"] not in data.get("message_ids", [])
        ]
        logging.debug("Cache after: %s", str(self.message_cache))
        self.update_messages_area()

    def prev_messages_page(self) -> None:
        if self.message_offset >= self.message_page_size:
            self.message_offset -= self.message_page_size
            logging.debug(
                "navigating to previous messages page, new offset %d",
                self.message_offset,
            )
            self.update_messages_area()

    def next_messages_page(self) -> None:
        self.message_offset += self.message_page_size
        logging.debug(
            "navigating to next messages page, new offset %d", self.message_offset
        )
        self.update_messages_area()

    def send_message(self, event: Optional[tk.Event] = None) -> None:
        content: str = self.message_entry.get().strip()
        logging.debug("attempting to send message: %s", content)
        if not self.selected_account:
            logging.error("no recipient selected when trying to send message")
            messagebox.showerror("error", "no recipient selected")
            return
        if not content:
            return
        try:
            new_id: int = self.proto_client.send_message(self.selected_account, content)
            logging.info(f"message sent to '{self.selected_account}'")
            new_msg: Dict[str, Any] = {
                "id": new_id,
                "from_": self.current_user,
                "to": self.selected_account,
                "timestamp": int(datetime.now().timestamp()),
                "content": content,
            }
            if not any(m["id"] == new_msg["id"] for m in self.message_cache):
                self.message_cache.append(new_msg)
        except Exception as e:
            logging.error(f"failed to send message: {e}")
            messagebox.showerror("error", f"failed to send message: {e}")
            return
        self.message_entry.delete(0, tk.END)
        self.update_messages_area()

    def delete_message(self, message_id: int) -> None:
        logging.info("attempting to delete message with id %d", message_id)
        try:
            self.proto_client.delete_message(message_id)
            self.message_cache = [
                msg for msg in self.message_cache if msg["id"] != message_id
            ]
        except Exception as e:
            logging.error("failed to delete message: %s", e)
            messagebox.showerror("error", f"failed to delete message: {e}")
            return
        self.update_messages_area()

    def open_settings(self) -> None:
        logging.debug("opening settings window")
        settings_win: tk.Toplevel = tk.Toplevel(self)
        settings_win.title("settings")
        settings_win.geometry("300x200")

        lbl: tk.Label = tk.Label(settings_win, text="messages per page:")
        lbl.pack(pady=10)
        per_page_entry: tk.Entry = tk.Entry(settings_win)
        per_page_entry.insert(0, str(self.message_page_size))
        per_page_entry.pack(pady=5)

        delete_btn: tk.Button = tk.Button(
            settings_win, text="delete account", command=self.delete_account
        )
        delete_btn.pack(pady=5)

        def save_settings() -> None:
            try:
                new_val: int = int(per_page_entry.get().strip())
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

        save_btn: tk.Button = tk.Button(
            settings_win, text="save", command=save_settings
        )
        save_btn.pack(pady=10)

    def delete_account(self) -> None:
        logging.info("deleting account '%s'", self.current_user)
        try:
            self.proto_client.delete_account(self.current_user)
        except Exception as e:
            logging.error("failed to delete account: %s", e)
            messagebox.showerror("error", f"failed to delete account: {e}")
            return
        messagebox.showinfo("account deleted", "your account has been deleted")
        if self.chat_frame:
            self.chat_frame.destroy()
        self._create_login_frame()

    def get_user_color(self, username: Optional[str]) -> str:
        if not username:
            return "red"
        if username not in self.user_color_map:
            idx: int = len(self.user_color_map) % len(USER_COLORS)
            self.user_color_map[username] = USER_COLORS[idx]
        return self.user_color_map[username]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="irc/gmail hybrid chat application")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose logging (default shows errors only)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="host address to connect to (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=12345,
        help="port to connect to (default: 12345)",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.ERROR
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.info("starting chat application")
    app: chatapp = chatapp(CustomProtocolClient, args.host, args.port)
    app.mainloop()
    logging.info("chat application closed")
