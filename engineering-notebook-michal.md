Date: Feb 3rd 2025

First entry. I'm new to this format so I will be refining it over time. I built a simple
prototype just to get my hands wet with client-server communication.
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
