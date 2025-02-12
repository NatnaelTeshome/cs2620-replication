Date: Feb 3rd 2025 (Michal)

First entry. I'm new to this format so I will be refining it over time. I built a simple
prototype just to get my hands wet with client-server communication. The prototype
is a basic Python server using selectors (my code was heavily inspired by lecture slides :) ).
Currently, I use a 4-byte length header to indicate the total size of the packet.
The actual packet payload is simply JSON.

What I tried doing:
- added some threading, so a separate server thread picks up each client connection
- implemented basic functionality (adding accounts, sending & reading messages)
- in-memory storage of messages (just a simple Python dict)

TODOs:
- refining all of this codebase
- a proper handshake between the client/server (don't want to store/send anything
in plaintext and be failed by Prof. Waldo)
- designing our custom wire protocol
- persistence of the database
- rest of the features (account deletion)
- defining semantics of pending/unread messages. what happens after account deletion?
- test suite
- documentation
- GUI other than terminal? Or maybe a simple TUI?

Questions for OH:
- do we have to use a Selector the way Prof. Waldo used it in the slides?

Date: Feb 5th (Natnael)

Currently, I am working on the TODOs from previous the previous entry. I took on some of
the backend tasks, mainly I started designing our custom write protocol. Refer took
. I took on some of
the backend tasks, mainly I started designing our custom write protocol. Refer to
the `Custom wire protocol documentation.pdf` file in the repo. There we talk
about the specific byte layout in the messages we send. There's a header, which contains
an opcode and a payload length; then according to the opcode, the payload can
be interpreted accordingly.


Date: Feb 5th 18:34 (Michal)

Started prototyping GUI with TKinter. It was a natural choice given it comes bundled
with the python package, is simple, and I've worked with it before! Also,
abstracted away the client class so that I can use a dummy client that always succeeds.
Turns out it works pretty well cross-platform wise too: I'm on a Mac and Natnael is
on a Windows machine, and because TKInter comes bundled with python we can both
run it and it looks mostly like a native app. Neat!

I've encountered some major difficulties with the GUI. Mainly, it isn't clear to me
how to handle an event loop (e.g. when my client receives an event from the server,
how do I handle the update of the GUI?). Currently, I simply spawn a separate 'listener'
thread that runs as a background daemon and listens to messages received from the server.
When the GUI instantiates the network client, it passes in a callback function which
is a pointer to a GUI method updating a message area. See `gui.py` for details.

TODOs:
- need to remember to remove the hardcoded localhost and port number


Date: Feb 6 19:50 (Michal)

Today was documentation day. I went through our code and added a bunch of docstrings everywhere, and then created the `documentation.md` file which talks more about the architecture of the server-client. I don't really delve into the protocol there, but I do talk about the interface the client library that my GUI uses is expected to implement. This is IMPORTANT (!!!) since it's against this interface that we (me & NatI) will be implementing two separate client libraries: one for JSON and one for our custom wire protocol. 


Date: Feb 6 8:30pm (Natnael)

Below, we detail some of the major design choices we made to build our application. There are many minor design tradeoffs we did, but these are the major ones. 

Creating account: We wanted to follow the instructions exactly, which is first allowing the username to enter their name and then if it’s used before rerouting them to the login page but if not to the signup page. Initially we didn’t implement the username check page, but we now have it.

We wanted to show multiple accounts in wildcard search. We implemented this on the left hand side of our GUI. Initially, we wanted to have the GUI specify the number of accounts in a specific wildcard. However, we decided it is visually more appealing from the GUI perspective if accounts are displayed until the full viewpoint is filled. Even though we have the protocol to select given number of accounts, the GUI uses this only implicitly.

For the read message functionality, instead of simply having a fixed number of read messages number, we allow the user to specify the number of unread messages to be displayed when they first login in the chat. We want to have this to allow the user flexibility as we want to build a user-centered solution.

Another functionality we added beyond the requirement is allowing the user to group each user they interact with. When we click on each account in the account display section, the user is taken into a separate chat window. Each chat window contains information

Multiplexing vs multithreading:

For minimal overhead and better I/O efficiency, we mainly use multiplexing (selectors in python- we got our motivation from the lectures) instead of simply having multithreading, which is not as scalable and has higher overhead in the server side. Even though multithreading was easier to implement, for scalability, we implement multiplexing, which is more complicated to implement than multithreading (so time was a tradeoff).

We implemented a live chat feature. This is enabled by client side multi-threading. If the user is logged in the user, the user is able to receive chat messages live without waiting. This requires the addition of push events, which are handled separately from, for example, messages that are sent while the user was logged out and that the user gets when they log in.

Persistence storage: we use a simple and efficient python library instead of having the overhead of databases like SQL (based on the suggestion from discussions on Ed)

*Please refer to the protocol documentation in the PDF of the repository to dive deep into our custom protocol design (we want to make this engineering notebook as concise as possible)*


Date: Feb 10th 13:49 (Michal)
I asked Natnael to start us on testing today, while I started work on implementing the client libnrary for our custom wire protocol. I had to make some modifications so that the server can notify clients in-real-time of new messages, if the clients are logged in. Hence, I reserve one of the opcodes as an EVENT opcode, which when the client receives, can be
treat as, well, a new event :) 
I also utilize the same mechanism to deliver notifications from the servre to the client about deleted messages. Per the Ed Post: [https://edstem.org/us/courses/69416/discussion/6107870](here), "Delete means it is gone, from both client and server, for both sender and receiver" per Prof. Waldo. As such, when a client starts a deletion of a message, I need that to propagate both to the server and to the other person the message relates to.


Feb 11 7PM (Natnael)
Most of the testing work is done. We use a fake 'MockClient' to perform the testing and fake a connection to the server.


----------------------------------------------------

Date: Feb 11th 16:00 (Michal)
Today I looked at the code to look for any synchronization issues, especially after adding
the new features. I found several places where our global shared state (like `global_message_id`,
`accounts`, and `id_to_message`) might be prone to race conditions. To address these, I introduced a global lock for all operations that modify our shared state.

Key change was  wrapping any modifications to `global_message_id` or `accounts` (especially in `handle_send`) within a `with lock:` block...

This is, of course, a  very coarse grained approach, and in a proper production-level
code we'd use something more fine grained. However, this is good enough to ensure correctness
and, even though crude, was the best we could do with our limited time limit to finish this projecc!!!


For anything not mentioned in this engineering ntoebook, please refer to
`documentation.md` and the custom protocol documentation in the 
`Custom wire protocol documentation.pdf` file in the repository. Thank you for reading!!!
