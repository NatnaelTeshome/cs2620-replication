import tkinter as tk
from tkinter import ttk, messagebox
import argparse
import logging
import sys
import queue
import hashlib
from pathlib import Path
from client import Client, DummyClient

def setup_logging(verbosity: int, log_file: str = None) -> None:
    """
    Configure logging based on verbosity level and optional log file.
    
    Args:
        verbosity: 0 (WARNING), 1 (INFO), 2 (DEBUG)
        log_file: Optional path to log file
    """
    levels = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG
    }
    level = levels.get(verbosity, logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Chat Client Application",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "--host",
        default="localhost",
        help="Server hostname or IP address"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=9999,
        help="Server port number"
    )
    
    parser.add_argument(
        "--dummy",
        action="store_true",
        help="Use dummy client instead of real network client"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase output verbosity (can be used multiple times)"
    )
    
    parser.add_argument(
        "--log-file",
        type=str,
        help="Path to log file (optional)"
    )
    
    parser.add_argument(
        "--theme",
        choices=["light", "dark"],
        default="light",
        help="GUI theme to use"
    )
    
    return parser.parse_args()


class ChatClientGUI(tk.Tk):
    """
    Main application window with login, signup, and chat frames.
    Handles client communication and message processing.
    """

    def __init__(self, args):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.args = args

        # Basic window setup
        self.title("Chat Client")
        self.geometry("800x600")
        self.minsize(600, 400)
        
        # Initialize queue and client
        self.incoming_queue = queue.Queue()
        self.setup_client()
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure('Title.TLabel', font=('Helvetica', 16, 'bold'))
        self.style.configure('Link.TLabel', foreground='blue', cursor='hand2')

        # Configure root window grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create main container
        self.main_container = ttk.Frame(self)
        self.main_container.grid(row=0, column=0, sticky="nsew")

        # Configure main container grid
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

        # Initialize frames
        self.frames = {}
        for F in (LoginFrame, SignupFrame, ChatFrame):
            frame = F(self.main_container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # Bind resize events and closing protocol
        self.bind("<Configure>", self.on_resize)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Start with login frame
        self.show_frame(LoginFrame)
        
        # Start polling the incoming queue
        self.poll_incoming_queue()
        
        self.logger.info("GUI initialized successfully")

    def setup_client(self):
        """Initialize the appropriate client based on arguments."""
        if self.args.dummy:
            self.logger.info("Using dummy client")
            self.client = DummyClient(self.incoming_queue)
        else:
            try:
                self.logger.info(f"Connecting to {self.args.host}:{self.args.port}")
                self.client = Client(self.args.host, self.args.port, self.incoming_queue)
                self.logger.info("Successfully connected to server")
            except Exception as e:
                self.logger.error(f"Failed to connect to server: {e}")
                if messagebox.askyesno(
                    "Connection Error",
                    "Failed to connect to server. Would you like to use dummy client instead?"
                ):
                    self.logger.info("Falling back to dummy client")
                    self.client = DummyClient(self.incoming_queue)
                else:
                    self.logger.info("User chose to exit after connection failure")
                    sys.exit(1)

    def on_resize(self, event):
        """Handle window resize events"""
        if event.widget == self:
            self.logger.debug(f"Resizing window to {event.width}x{event.height}")
            # Configure the frames themselves
            self.main_container.configure(width=event.width, height=event.height)
            
            # Update all frames to match the new size
            for frame in self.frames.values():
                frame.configure(width=event.width, height=event.height)

    def show_frame(self, frame_class):
        """Brings the specified frame to the front."""
        frame = self.frames[frame_class]
        self.logger.debug(f"Switching to {frame_class.__name__}")
        frame.tkraise()

    def poll_incoming_queue(self):
        """Process any incoming messages from the client"""
        try:
            while True:
                message = self.incoming_queue.get_nowait()
                self.process_incoming_message(message)
        except queue.Empty:
            pass
        self.after(100, self.poll_incoming_queue)

    def process_incoming_message(self, message):
        """Handle messages received from the client"""
        self.logger.debug(f"Processing message: {message}")
        
        if "status" in message:
            status = message.get("status")
            if status == "success":
                if message.get("command") == "validate_user":
                    chat_frame = self.frames[ChatFrame]
                    username = message.get("username")
                    exists = message.get("exists", False)
                    chat_frame.handle_user_validation(exists, username)
                else:
                    info = message.get("message", "")
                    if "Login successful" in info:
                        self.show_frame(ChatFrame)
                    messagebox.showinfo("Success", info)
            else:
                error = message.get("error", "Unexpected error")
                self.logger.warning(f"Error from server: {error}")
                messagebox.showerror("Error", error)
        
        elif "command" in message and message["command"] == "incoming_message":
            sender = message["data"].get("sender")
            text = message["data"].get("message")
            self.logger.debug(f"Received message from {sender}: {text}")
            chat_frame = self.frames[ChatFrame]
            chat_frame.handle_incoming_message(sender, text)
        
        elif message.get("type") == "connection_closed":
            self.logger.warning("Server closed the connection")
            messagebox.showwarning("Connection", "Server closed the connection")
        
        elif message.get("type") == "connection_error":
            error = message.get("error", "Unknown connection error")
            self.logger.error(f"Connection error: {error}")
            messagebox.showerror("Connection Error", error)

    def on_closing(self):
        """Handle window closing"""
        self.logger.info("Application shutting down")
        if self.client:
            self.client.close()
        self.destroy()


class LoginFrame(ttk.Frame):
    """Frame for user login."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.logger = logging.getLogger(__name__)
        
        # Make this frame expand to fill its container
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Create the center content frame
        content_frame = ttk.Frame(self)
        content_frame.grid(row=1, column=1)

        # Title
        title_label = ttk.Label(
            content_frame, 
            text="Login", 
            style='Title.TLabel'
        )
        title_label.pack(pady=(0, 20))

        # Login form
        form_frame = ttk.Frame(content_frame)
        form_frame.pack(fill="x", padx=20)

        # Username
        username_frame = ttk.Frame(form_frame)
        username_frame.pack(fill="x", pady=5)
        ttk.Label(username_frame, text="Username:").pack(side="left")
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(
            username_frame, 
            textvariable=self.username_var,
            width=20
        )
        self.username_entry.pack(side="left", padx=(10, 0))

        # Password
        password_frame = ttk.Frame(form_frame)
        password_frame.pack(fill="x", pady=5)
        ttk.Label(password_frame, text="Password:").pack(side="left")
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            password_frame,
            textvariable=self.password_var,
            show="*",
            width=20
        )
        self.password_entry.pack(side="left", padx=(10, 0))
        self.password_entry.bind("<Return>", lambda e: self.login())

        # Login button
        ttk.Button(
            content_frame,
            text="Login",
            command=self.login
        ).pack(pady=20)

        # Signup link
        signup_link = ttk.Label(
            content_frame,
            text="Don't have an account yet? Sign up here!",
            style='Link.TLabel'
        )
        signup_link.pack(pady=(0, 20))
        signup_link.bind(
            "<Button-1>",
            lambda e: controller.show_frame(SignupFrame)
        )

    def login(self):
        """Handle login attempt."""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        
        if not username or not password:
            self.logger.warning("Login attempted with empty fields")
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        self.logger.info(f"Attempting login for user: {username}")
        
        # Hash password and send login request
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.controller.client.send_request({
            "command": "login",
            "data": {
                "username": username,
                "password_hash": hashed_password
            }
        })
        
        # Clear fields
        self.username_var.set("")
        self.password_var.set("")


class SignupFrame(ttk.Frame):
    """Frame for account creation."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.logger = logging.getLogger(__name__)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Center container
        center_frame = ttk.Frame(self)
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Title
        title_label = ttk.Label(
            center_frame, text="Sign Up", style='Title.TLabel'
        )
        title_label.pack(pady=(0, 20))

        # Signup form
        form_frame = ttk.Frame(center_frame)
        form_frame.pack(fill="x", padx=20)

        # Username
        username_frame = ttk.Frame(form_frame)
        username_frame.pack(fill="x", pady=5)
        ttk.Label(username_frame, text="Username:").pack(side="left")
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(
            username_frame,
            textvariable=self.username_var,
            width=20
        )
        self.username_entry.pack(side="left", padx=(10, 0))

        # Password
        password_frame = ttk.Frame(form_frame)
        password_frame.pack(fill="x", pady=5)
        ttk.Label(password_frame, text="Password:").pack(side="left")
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            password_frame,
            textvariable=self.password_var,
            show="*",
            width=20
        )
        self.password_entry.pack(side="left", padx=(10, 0))

        # Confirm Password
        confirm_frame = ttk.Frame(form_frame)
        confirm_frame.pack(fill="x", pady=5)
        ttk.Label(confirm_frame, text="Confirm:").pack(side="left")
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(
            confirm_frame,
            textvariable=self.confirm_var,
            show="*",
            width=20
        )
        self.confirm_entry.pack(side="left", padx=(10, 0))
        self.confirm_entry.bind("<Return>", lambda e: self.create_account())

        # Create Account button
        ttk.Button(
            center_frame,
            text="Create Account",
            command=self.create_account
        ).pack(pady=20)

        # Login link
        login_link = ttk.Label(
            center_frame,
            text="Already have an account? Login here!",
            style='Link.TLabel'
        )
        login_link.pack(pady=(0, 20))
        login_link.bind(
            "<Button-1>",
            lambda e: controller.show_frame(LoginFrame)
        )

    def create_account(self):
        """Handle account creation attempt."""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        confirm = self.confirm_var.get().strip()
        
        if not username or not password or not confirm:
            self.logger.warning("Account creation attempted with empty fields")
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        if password != confirm:
            self.logger.warning("Password confirmation mismatch during account creation")
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        self.logger.info(f"Attempting to create account for user: {username}")
        
        # Hash password and send create account request
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.controller.client.send_request({
            "command": "create_account",
            "data": {
                "username": username,
                "password_hash": hashed_password
            }
        })
        
        # Clear fields
        self.username_var.set("")
        self.password_var.set("")
        self.confirm_var.set("")


class ChatFrame2(ttk.Frame):
    """Frame for chat interface with thread selection and conversation panels."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.logger = logging.getLogger(__name__)
        self.threads = {}  # Dictionary to store chat history
        self.current_thread = None

        # Configure main frame to expand
        self.pack_propagate(False)
        
        # Create horizontal paned window for resizable split
        self.paned = ttk.PanedWindow(self, orient="horizontal")
        self.paned.pack(fill="both", expand=True)

        # Left panel (Thread Selection)
        left_frame = ttk.Frame(self.paned)
        self.paned.add(left_frame, weight=1)

        # Configure left frame grid
        left_frame.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(1, weight=1)

        # Threads label
        ttk.Label(
            left_frame, text="Conversations", style='Title.TLabel'
        ).grid(row=0, column=0, pady=10, padx=5, sticky="w")

        # Thread list with scrollbar
        thread_frame = ttk.Frame(left_frame)
        thread_frame.grid(row=1, column=0, sticky="nsew", padx=5)
        thread_frame.grid_columnconfigure(0, weight=1)
        thread_frame.grid_rowconfigure(0, weight=1)

        self.thread_listbox = tk.Listbox(
            thread_frame,
            selectmode="single",
            activestyle="none",
            highlightthickness=1
        )
        self.thread_listbox.grid(row=0, column=0, sticky="nsew")
        thread_scrollbar = ttk.Scrollbar(
            thread_frame,
            orient="vertical",
            command=self.thread_listbox.yview
        )
        thread_scrollbar.grid(row=0, column=1, sticky="ns")
        self.thread_listbox.configure(yscrollcommand=thread_scrollbar.set)
        self.thread_listbox.bind('<<ListboxSelect>>', self.on_thread_select)

        # Search frame
        search_frame = ttk.Frame(left_frame)
        search_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=10)
        search_frame.grid_columnconfigure(0, weight=1)

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        search_entry.bind("<Return>", lambda e: self.start_thread())

        search_button = ttk.Button(
            search_frame, text="New Chat", command=self.start_thread
        )
        search_button.grid(row=0, column=1)

        # Right panel (Chat Area)
        right_frame = ttk.Frame(self.paned)
        self.paned.add(right_frame, weight=3)

        # Configure right frame grid
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(1, weight=1)

        # Chat header
        self.header_var = tk.StringVar(value="Select a conversation")
        self.header_label = ttk.Label(
            right_frame,
            textvariable=self.header_var,
            style='Title.TLabel'
        )
        self.header_label.grid(row=0, column=0, pady=10, padx=5, sticky="w")

        # Chat display with scrollbar
        chat_frame = ttk.Frame(right_frame)
        chat_frame.grid(row=1, column=0, sticky="nsew", padx=5)
        chat_frame.grid_columnconfigure(0, weight=1)
        chat_frame.grid_rowconfigure(0, weight=1)

        self.chat_display = tk.Text(
            chat_frame,
            wrap="word",
            state="disabled",
            padx=5,
            pady=5
        )
        self.chat_display.grid(row=0, column=0, sticky="nsew")
        
        chat_scrollbar = ttk.Scrollbar(
            chat_frame,
            orient="vertical",
            command=self.chat_display.yview
        )
        chat_scrollbar.grid(row=0, column=1, sticky="ns")
        self.chat_display.configure(yscrollcommand=chat_scrollbar.set)

        # Message entry
        message_frame = ttk.Frame(right_frame)
        message_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=10)
        message_frame.grid_columnconfigure(0, weight=1)

        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(
            message_frame,
            textvariable=self.message_var
        )
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_message())

        send_button = ttk.Button(
            message_frame,
            text="Send",
            command=self.send_message
        )
        send_button.grid(row=0, column=1)

    def start_thread(self):
        """Start a new conversation thread."""
        username = self.search_var.get().strip()
        if not username:
            self.logger.warning("Attempted to start thread with empty username")
            messagebox.showerror("Error", "Please enter a username")
            return
            
        self.logger.info(f"Validating user: {username}")
        self.controller.client.send_request({
            "command": "validate_user",
            "data": {"username": username}
        })

    def handle_user_validation(self, exists: bool, username: str):
        """Handle the response from user validation."""
        if exists:
            self.logger.info(f"User {username} validated, starting thread")
            if username not in self.threads:
                self.threads[username] = []
                self.thread_listbox.insert("end", username)
            self.current_thread = username
            self.header_var.set(f"Chat with {username}")
            self.search_var.set("")
            self.refresh_conversation_display()
        else:
            self.logger.warning(f"User {username} does not exist")
            messagebox.showerror("Error", f"User '{username}' does not exist")

    def on_thread_select(self, event):
        """Handle thread selection from the listbox."""
        selection = self.thread_listbox.curselection()
        if selection:
            username = self.thread_listbox.get(selection[0])
            self.logger.debug(f"Selected thread: {username}")
            self.current_thread = username
            self.header_var.set(f"Chat with {username}")
            self.refresh_conversation_display()

    def refresh_conversation_display(self):
        """Update the chat display with the current thread's messages."""
        self.chat_display.configure(state="normal")
        self.chat_display.delete(1.0, tk.END)
        
        if self.current_thread and self.current_thread in self.threads:
            for message in self.threads[self.current_thread]:
                self.chat_display.insert(tk.END, message + "\n")
                
        self.chat_display.configure(state="disabled")
        self.chat_display.see(tk.END)

    def handle_incoming_message(self, sender: str, text: str):
        """Handle an incoming message from another user."""
        self.logger.debug(f"Handling incoming message from {sender}: {text}")
        self.add_message(sender, f"{sender}: {text}")

    def add_message(self, thread: str, message: str):
        """Add a message to a thread and update display if necessary."""
        if thread not in self.threads:
            self.threads[thread] = []
            self.thread_listbox.insert("end", thread)
        self.threads[thread].append(message)
        if self.current_thread == thread:
            self.refresh_conversation_display()

    def send_message(self):
        """Handle sending a message in the current thread."""
        if not self.current_thread:
            self.logger.warning("Attempted to send message without selecting thread")
            messagebox.showerror("Error", "Please select a conversation first")
            return
            
        message = self.message_var.get().strip()
        if not message:
            return
            
        self.logger.debug(f"Sending message to {self.current_thread}: {message}")
        
        # Add message to local thread history
        self.add_message(self.current_thread, f"You: {message}")
        
        # Send message to server
        self.controller.client.send_request({
            "command": "send_message",
            "data": {
                "recipient": self.current_thread,
                "message": message
            }
        })
        
        # Clear message entry
        self.message_var.set("")


class ChatFrame(ttk.Frame):
    """Frame for chat interface with user list, thread selection, and conversation panels."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.logger = logging.getLogger(__name__)
        self.threads = {}  # Dictionary to store chat history
        self.current_thread = None
        self.online_users = set()  # Set to store online users

        # Configure main frame to expand
        self.pack_propagate(False)
        
        # Create horizontal paned window for resizable split
        self.paned = ttk.PanedWindow(self, orient="horizontal")
        self.paned.pack(fill="both", expand=True)

        # Left panel (User info, Thread Selection, Online Users)
        left_frame = ttk.Frame(self.paned)
        self.paned.add(left_frame, weight=1)

        # Configure left frame grid
        left_frame.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(2, weight=1)  # Threads list gets more space
        left_frame.grid_rowconfigure(4, weight=1)  # Users list gets space too

        # User info and settings
        user_frame = ttk.Frame(left_frame)
        user_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        user_frame.grid_columnconfigure(0, weight=1)

        # Username label
        username_label = ttk.Label(
            user_frame,
            text="DEBUGTODO",
            style='Title.TLabel'
        )
        username_label.grid(row=0, column=0, sticky="w", padx=5)

        # Settings button with unicode character
        settings_btn = ttk.Button(
            user_frame,
            text="⚙️",
            width=3,
            command=self.open_settings
        )
        settings_btn.grid(row=0, column=1, padx=5)

        # Threads section
        ttk.Label(
            left_frame,
            text="Conversations",
            style='Title.TLabel'
        ).grid(row=1, column=0, pady=(10,5), padx=5, sticky="w")

        # Thread list with scrollbar
        thread_frame = ttk.Frame(left_frame)
        thread_frame.grid(row=2, column=0, sticky="nsew", padx=5)
        thread_frame.grid_columnconfigure(0, weight=1)
        thread_frame.grid_rowconfigure(0, weight=1)

        self.thread_listbox = tk.Listbox(
            thread_frame,
            selectmode="single",
            activestyle="none",
            highlightthickness=1
        )
        self.thread_listbox.grid(row=0, column=0, sticky="nsew")
        thread_scrollbar = ttk.Scrollbar(
            thread_frame,
            orient="vertical",
            command=self.thread_listbox.yview
        )
        thread_scrollbar.grid(row=0, column=1, sticky="ns")
        self.thread_listbox.configure(yscrollcommand=thread_scrollbar.set)
        self.thread_listbox.bind('<<ListboxSelect>>', self.on_thread_select)

        # Search frame
        search_frame = ttk.Frame(left_frame)
        search_frame.grid(row=3, column=0, sticky="ew", padx=5, pady=10)
        search_frame.grid_columnconfigure(0, weight=1)

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        search_entry.bind("<Return>", lambda e: self.start_thread())

        search_button = ttk.Button(
            search_frame, text="New Chat", command=self.start_thread
        )
        search_button.grid(row=0, column=1)

        # Online Users section
        ttk.Label(
            left_frame,
            text="Online Users",
            style='Title.TLabel'
        ).grid(row=4, column=0, pady=(10,5), padx=5, sticky="w")

        # Online users list with scrollbar
        users_frame = ttk.Frame(left_frame)
        users_frame.grid(row=5, column=0, sticky="nsew", padx=5, pady=(0, 5))
        users_frame.grid_columnconfigure(0, weight=1)
        users_frame.grid_rowconfigure(0, weight=1)

        self.users_listbox = tk.Listbox(
            users_frame,
            selectmode="single",
            activestyle="none",
            highlightthickness=1
        )
        self.users_listbox.grid(row=0, column=0, sticky="nsew")
        users_scrollbar = ttk.Scrollbar(
            users_frame,
            orient="vertical",
            command=self.users_listbox.yview
        )
        users_scrollbar.grid(row=0, column=1, sticky="ns")
        self.users_listbox.configure(yscrollcommand=users_scrollbar.set)
        self.users_listbox.bind('<Double-Button-1>', self.start_thread_from_users)

        # Right panel (Chat Area)
        right_frame = ttk.Frame(self.paned)
        self.paned.add(right_frame, weight=3)

        # Configure right frame grid
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(1, weight=1)

        # Chat header
        self.header_var = tk.StringVar(value="Select a conversation")
        self.header_label = ttk.Label(
            right_frame,
            textvariable=self.header_var,
            style='Title.TLabel'
        )
        self.header_label.grid(row=0, column=0, pady=10, padx=5, sticky="w")

        # Chat display with scrollbar
        chat_frame = ttk.Frame(right_frame)
        chat_frame.grid(row=1, column=0, sticky="nsew", padx=5)
        chat_frame.grid_columnconfigure(0, weight=1)
        chat_frame.grid_rowconfigure(0, weight=1)

        self.chat_display = tk.Text(
            chat_frame,
            wrap="word",
            state="disabled",
            padx=5,
            pady=5
        )
        self.chat_display.grid(row=0, column=0, sticky="nsew")
        
        chat_scrollbar = ttk.Scrollbar(
            chat_frame,
            orient="vertical",
            command=self.chat_display.yview
        )
        chat_scrollbar.grid(row=0, column=1, sticky="ns")
        self.chat_display.configure(yscrollcommand=chat_scrollbar.set)

        # Message entry
        message_frame = ttk.Frame(right_frame)
        message_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=10)
        message_frame.grid_columnconfigure(0, weight=1)

        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(
            message_frame,
            textvariable=self.message_var
        )
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_message())

        send_button = ttk.Button(
            message_frame,
            text="Send",
            command=self.send_message
        )
        send_button.grid(row=0, column=1)

        # Request initial online users list
        self.request_online_users()

    def open_settings(self):
        """Open the settings dialog"""
        self.logger.debug("Opening settings dialog")
        settings_dialog = SettingsDialog(self, self.controller)
        settings_dialog.grab_set()  # Make dialog modal

    def update_online_users(self, users_list):
        """Update the online users listbox with new list of users"""
        self.logger.debug(f"Updating online users list: {users_list}")
        self.users_listbox.delete(0, tk.END)
        self.online_users = set(users_list)
        for user in sorted(users_list):
            if user != self.controller.username:  # Don't show current user
                self.users_listbox.insert(tk.END, user)

    def request_online_users(self):
        """Request the current list of online users from the server"""
        self.logger.debug("Requesting online users list")
        self.controller.client.send_request({
            "command": "get_online_users",
            "data": {}
        })

    def start_thread_from_users(self, event):
        """Start a new chat thread from double-clicking a user in the online users list"""
        selection = self.users_listbox.curselection()
        if selection:
            username = self.users_listbox.get(selection[0])
            self.search_var.set(username)
            self.start_thread()

    def start_thread(self):
        """Start a new conversation thread."""
        username = self.search_var.get().strip()
        if not username:
            self.logger.warning("Attempted to start thread with empty username")
            messagebox.showerror("Error", "Please enter a username")
            return
            
        self.logger.info(f"Validating user: {username}")
        self.controller.client.send_request({
            "command": "validate_user",
            "data": {"username": username}
        })

    def handle_user_validation(self, exists: bool, username: str):
        """Handle the response from user validation."""
        if exists:
            self.logger.info(f"User {username} validated, starting thread")
            if username not in self.threads:
                self.threads[username] = []
                self.thread_listbox.insert("end", username)
            self.current_thread = username
            self.header_var.set(f"Chat with {username}")
            self.search_var.set("")
            self.refresh_conversation_display()
        else:
            self.logger.warning(f"User {username} does not exist")
            messagebox.showerror("Error", f"User '{username}' does not exist")

    def on_thread_select(self, event):
        """Handle thread selection from the listbox."""
        selection = self.thread_listbox.curselection()
        if selection:
            username = self.thread_listbox.get(selection[0])
            self.logger.debug(f"Selected thread: {username}")
            self.current_thread = username
            self.header_var.set(f"Chat with {username}")
            self.refresh_conversation_display()

    def refresh_conversation_display(self):
        """Update the chat display with the current thread's messages."""
        self.chat_display.configure(state="normal")
        self.chat_display.delete(1.0, tk.END)
        
        if self.current_thread and self.current_thread in self.threads:
            for message in self.threads[self.current_thread]:
                self.chat_display.insert(tk.END, message + "\n")
                
        self.chat_display.configure(state="disabled")
        self.chat_display.see(tk.END)

    def handle_incoming_message(self, sender: str, text: str):
        """Handle an incoming message from another user."""
        self.logger.debug(f"Handling incoming message from {sender}: {text}")
        self.add_message(sender, f"{sender}: {text}")

    def add_message(self, thread: str, message: str):
        """Add a message to a thread and update display if necessary."""
        if thread not in self.threads:
            self.threads[thread] = []
            self.thread_listbox.insert("end", thread)
        self.threads[thread].append(message)
        if self.current_thread == thread:
            self.refresh_conversation_display()

    def send_message(self):
        """Handle sending a message in the current thread."""
        if not self.current_thread:
            self.logger.warning("Attempted to send message without selecting thread")
            messagebox.showerror("Error", "Please select a conversation first")
            return
            
        message = self.message_var.get().strip()
        if not message:
            return
            
        self.logger.debug(f"Sending message to {self.current_thread}: {message}")
        
        # Add message to local thread history
        self.add_message(self.current_thread, f"You: {message}")
        
        # Send message to server
        self.controller.client.send_request({
            "command": "send_message",
            "data": {
                "recipient": self.current_thread,
                "message": message
            }
        })
        
        # Clear message entry
        self.message_var.set("")


class SettingsDialog(tk.Toplevel):
    """Dialog window for user settings and preferences."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.logger = logging.getLogger(__name__)

        # Configure dialog
        self.title("Settings")
        self.geometry("400x500")
        self.minsize(300, 400)
        self.resizable(False, False)

        # Make dialog modal
        self.transient(parent)
        self.focus_set()

        # Main container
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill="both", expand=True)

        # Notebook for different settings categories
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill="both", expand=True, pady=(0, 10))

        # Account Settings
        account_frame = ttk.Frame(notebook, padding="10")
        notebook.add(account_frame, text="Account")

        # Username (display only)
        ttk.Label(account_frame, text="Username:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Label(
            account_frame,
            text=controller.username,
            style="Bold.TLabel"
        ).grid(row=0, column=1, sticky="w", pady=5)

        # Change Password
        ttk.Label(account_frame, text="Current Password:").grid(
            row=1, column=0, sticky="w", pady=5
        )
        self.current_password = ttk.Entry(account_frame, show="*")
        self.current_password.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Label(account_frame, text="New Password:").grid(
            row=2, column=0, sticky="w", pady=5
        )
        self.new_password = ttk.Entry(account_frame, show="*")
        self.new_password.grid(row=2, column=1, sticky="ew", pady=5)

        ttk.Label(account_frame, text="Confirm Password:").grid(
            row=3, column=0, sticky="w", pady=5
        )
        self.confirm_password = ttk.Entry(account_frame, show="*")
        self.confirm_password.grid(row=3, column=1, sticky="ew", pady=5)

        ttk.Button(
            account_frame,
            text="Change Password",
            command=self.change_password
        ).grid(row=4, column=0, columnspan=2, pady=20)

        # Appearance Settings
        appearance_frame = ttk.Frame(notebook, padding="10")
        notebook.add(appearance_frame, text="Appearance")

        # Theme selection
        ttk.Label(appearance_frame, text="Theme:").grid(
            row=0, column=0, sticky="w", pady=5
        )
        self.theme_var = tk.StringVar(value=self.controller.args.theme)
        theme_combo = ttk.Combobox(
            appearance_frame,
            textvariable=self.theme_var,
            values=["light", "dark"],
            state="readonly"
        )
        theme_combo.grid(row=0, column=1, sticky="ew", pady=5)
        theme_combo.bind("<<ComboboxSelected>>", self.change_theme)

        # Notifications Settings
        notifications_frame = ttk.Frame(notebook, padding="10")
        notebook.add(notifications_frame, text="Notifications")

        # Enable/disable notifications
        self.notifications_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            notifications_frame,
            text="Enable Notifications",
            variable=self.notifications_enabled,
            command=self.toggle_notifications
        ).grid(row=0, column=0, sticky="w", pady=5)

        # Sound notifications
        self.sound_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            notifications_frame,
            text="Enable Sound",
            variable=self.sound_enabled,
            command=self.toggle_sound
        ).grid(row=1, column=0, sticky="w", pady=5)

        # Close button
        ttk.Button(
            main_frame,
            text="Close",
            command=self.destroy
        ).pack(side="right", pady=(0, 5))

    def change_password(self):
        """Handle password change request"""
        current = self.current_password.get()
        new = self.new_password.get()
        confirm = self.confirm_password.get()

        if not all([current, new, confirm]):
            messagebox.showerror("Error", "All password fields are required")
            return

        if new != confirm:
            messagebox.showerror("Error", "New passwords do not match")
            return

        self.logger.info("Attempting to change password")
        self.controller.client.send_request({
            "command": "change_password",
            "data": {
                "current_password": hashlib.sha256(current.encode()).hexdigest(),
                "new_password": hashlib.sha256(new.encode()).hexdigest()
            }
        })

    def change_theme(self, event=None):
        """Handle theme change"""
        theme = self.theme_var.get()
        self.logger.info(f"Changing theme to: {theme}")
        try:
            self.controller.tk.call("set_theme", theme)
        except tk.TclError as e:
            self.logger.error(f"Failed to change theme: {e}")
            messagebox.showerror("Error", "Failed to change theme")

    def toggle_notifications(self):
        """Handle notifications toggle"""
        enabled = self.notifications_enabled.get()
        self.logger.info(f"Notifications {'enabled' if enabled else 'disabled'}")
        # Implement notification settings

    def toggle_sound(self):
        """Handle sound toggle"""
        enabled = self.sound_enabled.get()
        self.logger.info(f"Sound {'enabled' if enabled else 'disabled'}")
        # Implement sound settings

def main():
    """Main entry point for the application."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.verbose, args.log_file)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting Chat Client Application")
    logger.debug(f"Arguments: {args}")
    
    # Create and run the application
    app = ChatClientGUI(args)
    
    # Try to set the theme if specified
    if args.theme:
        try:
            theme_file = Path(__file__).parent / f"{args.theme}.tcl"
            if theme_file.exists():
                logger.info(f"Loading theme: {args.theme}")
                app.tk.call("source", str(theme_file))
                app.tk.call("set_theme", args.theme)
            else:
                logger.warning(f"Theme file not found: {theme_file}")
        except tk.TclError as e:
            logger.error(f"Failed to load theme: {e}")
    
    try:
        app.mainloop()
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        raise
    finally:
        logger.info("Application shutting down")


if __name__ == "__main__":
    main()
