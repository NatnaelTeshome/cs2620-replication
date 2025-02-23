# HW2 
### Link to the code
Our codebase can be found in the following [public GitHub repository](https://github.com/MKJM2/cs2620-wire-protocols):
```
https://github.com/MKJM2/cs2620-wire-protocols
```

# Does the use of this tool (gRPC) make the application easier or more difficult?
Definitely easier. Serialization/deserialization seemed to us like a very 'automatable' work,
so having something do most of the work for us, so we can focus on the actual interface, is great!

### Ease of implementation & Extensibility
No need to write a custom parser, like for our binary protocol!

JSON is easy to extend (just add new fields).
Our wire protocol isn't necessarily hard to extend, but definitely annoying
(have to implement additional encoding/decoding logic for e.g. every single new op_code we want support).
Protobuf/gRPC is super easy to extend. Just change the `.proto` definition and recompile
the code! The decoding/encoding logic is done for you. Reminds me of using `serde` in Rust.

### What does it do to the size of the data passed? Memory usage benchmarking
Benchmarking against the JSON and our custom protocols:

A problem with benchmarking is that many of the message types have variable/unbound length.
E.g. a client sending a message can send a message of any arbitrary length.

What we decided to do after some deliberation is the following:

for message types (opcodes) where the length isn't variable, we provide
a detailed size comparison in the following table. 

Note that for this analysis we use the insecure gRPC channels, and so do not
account for e.g. TLS encryption overhead (or HTTP/2 headers). We only look
at the amount of bytes in the actual payload. Note also that this analysis
isn't fully fair, since operating on raw sockets is working directly
on Layer 4 (Transport Layer) of the OSI model (i.e. UDP or TCP),
whereas gRPC is an application-layer protocol (layer 7), built on-top of HTTP/2.

This makes comparing the protocols tricky: gRPC by virtue of being on a higher layer,
by design provides more features like e.g. multiplexing, flow control, or built-in support
for streaming. The protocols operate at different levels of abstraction!

This is why we decided to compare the raw serialization efficiency. So, we'll compare
the size of the JSON dump, to our binary payload, to the size of the protobuf sent over the network.

TODO: Table
| Column1 | Column2 | Column3 |
| ------------- | -------------- | -------------- |
| Item1 | Item1 | Item1 |

To account for variability in message sizes, we test all three protocols on a range of  
realistic scenarios + some edge cases.

Realistic scenarios: 

1. Small messages, like a simple "Hello". These will highlight the overhead of the headers/metadata 
for each protocol, which will comprise a large amount of bytes sent over the network

2.  Medium messages: A typical chat message consisting of a few words / up to a sentence.
, or a single page of accounts for the LIST_ACCOUNTS operator. Represents the average case request
sent.

3. Large messages: A list of hundreds of accounts, or big messages consisting of multiple English sentences. Fetching
chat unread messages where there is 100+ unread messages.
``
Edge cases: empty payloads for each protocol allowing payloads. This should give us a good estimate
of the specific number of overhead bytes in each protocol. E.g. sending an empty string as a message (no bytes, payload length
of 0 in our custom wire protocol).
Maximum sized payloads for each protocol. This should, in theory, show us experimentally, that in the limit
the size of the overhead doesn't matter, as it's constant (TODO: Verify that this is true!), and the size
of the actual message contents will overshadow everything else.


### How does it change the structure of the client? The server?

### How does this change the testing of the application?










