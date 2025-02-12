Harrison and Henry (table 2)
Does it work? (2 points)


Does it do all that was specified?



Does it run on multipel machines?

Is the documentation clear? (1 point)

Are the tests adequate? (1 point)

Is the code clear and clean? (1 point)


Nice, friendly GUI

a little delay when sending requests
to the server running on localhost?

TKInter, nice! Clean
Buttons for settings, log out, accoutn deletion

GMAIL style: with a recipient and textarea field.

A separate inbox field that gets manually refreshed.

Highlighted by color which ones you sent versus which one you received

Is able to change the number of displayed messages (Through the Settings tab),
so that requirement is satisfied

Deletion works. Sending / receiving messages between accounts works.

Scrollable chats to limit the number of messages dispalyed to the client!

-----

Code walkthrough (Harry & Harrison, table 2)


very good config
includes configureable magic numbers, limits on message size

backend uses a threadpool, even on the client to make sure IO is asynchronous

queue for synchronization

super clean code

uses advanced Python concepts like `@classmethod`

clean, very readable

THIS CODE REVIEW NEEDS TO INCLUDE EXPLANATIONS, NOT JSUT A NUMERICAL SCORE
SHOULD ANSWER THE QUESTIONS AT THE TOP OF THE FILE

As for tests: a bunch of unit tests

tesst for messaging code

using pytest fixtures

test functionality of the client/server acctions

they mock the server side for some of the tests

even a test_database file to make sure the database behaves as expected:
do not alowing duplicate accounts

do not allow duplicate conversations

handle edge cases like: deleting the last message in a conversation should delete the entire conversation


Good documentation. They make the endpoints very explicit



they design the database structure (use SQLITE), description of the schemas used


They Describe all server and client components, as well as the action interface



We got proof that it works over the internet.



_________
(Jayson Lin + EDward Kang, Table 2)

Had a GUI but run out of time to make it work over the network?
Though they did design a GUI...

But they do have a working CLI client

Working communication between client and server on localhost was demonstrated.

Reasonable workflow

Passwords get correctly hashed (so satisfies requirement)

account creation automatically links you to your message dashboard

demonstrated workign account membership test (whether username exists or not)

Logging in works.

A message dashboard:

GMAIL style interface, with separate unread and read columns.


Requirement: specify number of unread messages.
They satisfy that with a `unreadcount` command that is called from the CLI.

It will automatically fetch the number of unread messages.

Clicking on a message does read it

they support a `list` command for listing all the existing usernames.


They have a very good wire protocol with a table describing all the op_codes,
required fields in the payload, and description (in a Google Doc format,
though I don't know how they will suply it from their repo for the submission)

use utf-8 encoding / decoding 
























