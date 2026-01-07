Packet Sniffer & Analyzer

A lightweight packet sniffer and protocol analyzer with support for HTTP, DNS, and TLS metadata parsing. The goal of this project is to understand networking internals by manually decoding packet headers instead of relying on high-level libraries.

Objectives

- Capture raw packets from the network interface
- Decode Ethernet and IPv4 headers
- Extract protocol information (TCP / UDP)
- Later: parse HTTP, DNS, and TLS metadata
- Build filtering and basic traffic statistics

Current Features
- Raw packet capture (Linux AF_PACKET)
- Ethernet frame parsing
- IPv4 header parsing
- TCP header parsing with ports and sequence numbers
- UDP header parsing with port extraction
- HTTP request line detection
- DNS query extraction
- TLS ClientHello SNI extraction

