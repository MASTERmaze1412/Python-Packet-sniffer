Here’s a more natural version that sounds like a developer describing a project they actually built, rather than formal technical documentation. It keeps the important technologies, protocols, setup instructions, and two future enhancements.

# 🛡️ Network Packet Sniffer & Analyzer

A Python project I had built to understand how network traffic works behind the scenes. It can capture live packets, break them down into their different protocols, scan a local network for active devices, and create custom TCP/UDP packets for testing.

### 🛠️ Technologies & Protocols

- `Python` — Main programming language
- `Scapy` — Packet crafting and ARP scanning
- `Socket Programming` — Capturing raw network packets
- `struct` — Reading and unpacking packet headers
- `Ethernet & IPv4` — Understanding network frames and IP packets
- `TCP & UDP` — Inspecting transport-layer communication
- `ICMP` — Examining network control messages
- `ARP` — Discovering devices on a local network
- `HTTP` — Inspecting basic unencrypted HTTP traffic
- `PCAP` — Saving captured packets for later analysis

### 🚀 Features

- Capture live network packets and inspect their contents
- View source and destination IP and MAC addresses
- Inspect TCP ports, sequence numbers, acknowledgment numbers, and flags
- Analyze UDP and ICMP packets
- View readable or hexadecimal packet payloads
- Save captured traffic to PCAP files
- Discover active devices on a local network using ARP
- Create and send custom TCP/UDP packets with configurable IP addresses and ports

### 📌 The Process

I wanted to understand what actually happens when devices communicate over a network, beyond what we usually see in applications. So, I built a command-line tool that captures packets and breaks their contents into readable information.

One of the interesting parts was working with raw packet data. Using Python's `struct` module, I unpack Ethernet, IPv4, TCP, and UDP headers to extract information such as addresses, ports, and TCP flags.

I also used Scapy to handle packet crafting and ARP-based network discovery. To make the tool more useful for analysis, I added the ability to save captured packets in PCAP format so they can be opened later in Wireshark.

The project helped me get more comfortable with network protocols, binary data, socket programming, and the way different layers of network communication fit together.

### 🔬 Protocols & Methods

- **Raw sockets:** Capture Ethernet frames directly on supported Linux systems.
- **Packet parsing:** Extract protocol fields using Python's binary data handling.
- **TCP flag analysis:** Inspect SYN, ACK, FIN, RST, PSH, and URG flags.
- **ARP scanning:** Find devices that respond to broadcast ARP requests on a local network.
- **Packet crafting:** Build custom IPv4 packets containing TCP or UDP segments using Scapy.
- **PCAP writing:** Save captured packets for offline inspection and debugging.

### 📂 Project Structure

```
Network-Packet-Analyzer/
└── packet_sniffer_cyber1.py
```

The current implementation is contained in a single Python script, with separate functions for packet capture, protocol parsing, packet saving, network scanning, and packet crafting.

### 💻 Running the Project

**Prerequisites**

- Python 3
- Linux for the current raw Ethernet capture implementation
- Scapy
- Appropriate privileges for raw packet operations

**1. Install Scapy**

```
python3 -m pip install scapy
```

**2. Run the script**

Save the code as `packet_sniffer_cyber1.py` and run:

```
sudo python3 packet_sniffer_cyber1.py
```

Root privileges may be required for packet capture, packet transmission, and network scanning.

### 🖥️ Using the Tool

When you start the program, a menu gives you five options:

1. **Start Sniffing** — Capture live packets and inspect their headers and payloads.
2. **Save Captured Packets** — Export previously captured packets to a PCAP file.
3. **Forge and Send Packet** — Create a custom TCP or UDP packet by entering its source and destination IP addresses, ports, and optional payload.
4. **Scan for Active Devices** — Enter a local network range, such as `192.168.1.0/24`, to find devices responding to ARP requests.
5. **Exit** — Close the program.

### 🧪 Testing

A few ways to explore and test the project:

- Capture TCP traffic and observe how ports and flags change.
- Inspect UDP and ICMP packets when they appear on the selected interface.
- Scan your own local network and compare the discovered devices with known hosts.
- Save a packet capture and open it in Wireshark.
- Test packet construction in an isolated lab or on systems you have permission to assess.

### ⚠️ Limitations

- The current raw packet capture method uses Linux-specific `AF_PACKET` sockets.
- IPv6 and several other protocols are not fully supported by the custom parser.
- HTTPS traffic is encrypted, so the tool cannot read its application data.
- ARP scanning is limited to the local network segment.
- Packet parsing has limited handling for malformed or incomplete packets.
- The current stop mechanism uses an input prompt; pressing `q` is not implemented as an active keyboard shortcut.

### 💡 Future Enhancements

**1. Better Packet Filtering and Analysis**

Add filters for IP addresses, ports, and protocols, along with support for more protocols such as DNS and IPv6. This would make it easier to focus on specific traffic instead of reading every captured packet.

**2. A Live Traffic Dashboard**

Build a simple graphical interface showing packet rates, protocol distribution, active devices, and traffic history. This would make the tool easier to use and help users spot unusual activity without relying entirely on terminal output.

### 📚 References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Python Socket Documentation](https://docs.python.org/3/library/socket.html)
- [Python ](https://docs.python.org/3/library/struct.html)[`struct`](https://docs.python.org/3/library/struct.html)[ Documentation](https://docs.python.org/3/library/struct.html)
- [Wireshark](https://www.wireshark.org/)
- [RFC 791 — Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [RFC 768 — User Datagram Protocol](https://www.rfc-editor.org/rfc/rfc768)
- [RFC 826 — Address Resolution Protocol](https://www.rfc-editor.org/rfc/rfc826)

### 🔐 Responsible Use

this project is built for learning about networking and experimenting with packet analysis. Use it only on networks and devices you own or have permission to test, especially when capturing traffic or sending custom packets.

### 👨‍💻 About

A hands-on Python project focused on understanding network protocols, raw sockets, packet parsing, and basic network discovery.
