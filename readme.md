# Packet Probe

**Packet Probe** is a Python-based tool designed to parse and analyze raw network packets. It supports multiple protocols, including IPv4, IPv6, ARP, RARP, TCP, UDP, PPP, VLAN, MPLS, and others. This tool is intended for network administrators, security professionals, and anyone looking to analyze network traffic and perform deep packet inspection.

## Features

- **Protocol Support**:
  - IPv4
  - IPv6
  - ARP
  - RARP
  - TCP/UDP
  - PPP
  - VLAN
  - MPLS Unicast/Multicast
  - LLDP
  - EAPOL

- **Packet Information**:
  - Displays detailed information about each protocol layer (e.g., IP, TCP, VLAN, etc.)
  - Pretty-prints parsed data in a human-readable format
  - Displays source and destination MAC addresses
  - Supports parsing payload data based on protocol type

- **Customizable Output**:
  - Option to print detailed protocol-specific information
  - Option to choose between different verbosity levels (e.g., `debug`, `info`)

- **Packet Parsing and Analysis**:
  - Parses raw packet data and extracts protocol headers
  - Support for identifying frame types and protocols like TCP, UDP, and ARP

## Command-Line Usage

`Packet Probe` can be run directly from the command line with the following options:

### Options:
- `-i, --interface <interface>`: Specify the network interface to capture packets from (e.g., `eth0`).
- `-h, --help`: Display the help information and available options.

### Example:
```bash
sudo python3 packetprobe.py -i eth0
