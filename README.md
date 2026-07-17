# DNS Server from Scratch 

A fully functional Domain Name System (DNS) server implemented entirely from scratch in Python, handling raw UDP packets at the byte level

## Overview
This project was built to gain a deep, bare-metal understanding of network protocols. Instead of relying on high-level DNS libraries, this server manually parses and constructs DNS messages bit-by-bit according to **RFC 1035**. It functions both as an authoritative responder and a DNS forwarder.

## Key Features
* **Socket Programming :** Handles incoming UDP connections gracefully
* **Byte-level Parsing :** Slices and reads raw byte streams directly from the network buffer
* **Bit Manipulation :** Uses bitwise operations (Shifts `<<`, Masks `&`) to construct complex DNS Headers and Flags without third-party tools
* **DNS Compression Handling :** Implements a recursive decompression algorithm to parse DNS pointers (`0xC0`) and resolve compressed domain names
* **DNS Forwarding :** Acts as a DNS proxy, routing client queries to external resolvers and seamlessly merging the responses
* **Zero Dependencies :** Built exclusively using Python's standard library (`socket`, `sys`)

## Technical Implementation
* **Header Construction :** Accurately crafts the 12-byte DNS header dynamically
* **Multiple Queries Parsing :** Iterates through and processes multiple questions sequentially within a single datagram
* **Answer Section Generation :** Dynamically generates Resource Records (A Records) with proper TTL and RDATA formatting in Big-Endian byte order

## How to Run
```bash
# Start the local server
python3 src/dns_server.py

# Start as a Forwarder to an external resolver (e.g., Google DNS)
python3 src/dns_server.py --resolver 8.8.8.8:53
```

## How to Test the Server

Once the server is running, you can test it by sending DNS queries from another terminal window

###  For (Linux / macOS)

```bash
# Query the local server for google.com
dig @127.0.0.1 -p 2053 google.com A

# Query the local server with multiple domains
dig @127.0.0.1 -p 2053 google.com yahoo.com A
```

### For Windwos 

```bash
# Start an interactive nslookup session directed at your local server
nslookup -port=2053

# Inside the prompt, type the domain you want to query:
> google.com
```

## Expected Output (Ex using dig)

```bash
;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             60      IN      A       8.8.8.8

;; Query time: 1 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1) (UDP)
```