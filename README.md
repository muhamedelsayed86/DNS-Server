# DNS Server from Scratch 

A fully functional Domain Name System (DNS) server implemented entirely from scratch in Python, handling raw UDP packets at the byte level 

##  Overview
This project was built to gain a deep, bare-metal understanding of network protocols. Instead of relying on high-level DNS libraries, this server manually parses and constructs DNS messages bit-by-bit according to **RFC 1035**

##  Key Features
* **Socket Programming :** Handles incoming UDP connections gracefully
* **Byte-level Parsing :** Slices and reads raw byte streams directly from the network buffer
* **Bit Manipulation :** Uses bitwise operations (Shifts `<<`, Masks `&`) to construct complex DNS Headers and Flags without third-party tools
* **Length-Prefixed Domain Encoding :** Implements custom parsing for DNS domain name sequences.
* **Zero Dependencies :** Built exclusively using Python's standard library (`socket`)

##  Technical Implementation
* **Header Construction :** Accurately crafts the 12-byte DNS header
* **Question Section :** Decodes client queries (e.g., `google.com`)
* **Answer Section :** Dynamically generates Resource Records (A Records) with proper TTL and RDATA formatting in Big-Endian byte order

##  How to Run
```bash
# Start the server (Listens on port 2053 by default)
python3 dns_server.py