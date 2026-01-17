# C-Shark

A command-line network packet analyzer built in C, providing real-time packet capture and deep protocol analysis.

## Quick Start

### Building and Running

```bash
# Clone or navigate to the project directory
cd C-Shark

# Install dependencies (Debian/Ubuntu)
sudo apt-get install libpcap-dev gcc make

# Build the project
make

# Run C-Shark (requires root privileges)
sudo ./cshark
```

### Quick Example

```bash
# 1. Start C-Shark
sudo ./cshark

# 2. Select a network interface (e.g., eth0, wlan0)
Select an interface to sniff (1-3): 1

# 3. Choose capture mode
Enter choice (1-4): 1    # Start capturing all packets

# 4. Stop capture
Press Ctrl+C to stop

# 5. Inspect captured packets or exit
Enter choice (1-4): 3    # Inspect last session
Enter choice (1-4): 4    # Exit
```

## Overview

C-Shark is a lightweight packet sniffer that captures and analyzes network traffic at multiple protocol layers. It leverages libpcap for packet capture and provides detailed inspection of Ethernet, ARP, IPv4, IPv6, TCP, UDP, and application-layer protocols.

## Features

### Protocol Support
- **Layer 2**: Ethernet frame analysis
- **Layer 2.5**: ARP packet inspection (requests and replies)
- **Layer 3**: IPv4 and IPv6 packet analysis
- **Layer 4**: TCP and UDP segment/datagram analysis
- **Layer 7**: Application protocol detection (HTTP, HTTPS, DNS, FTP, SSH, Telnet, SMTP, POP3, IMAP)

### Capture Capabilities
- Interface selection from available network devices
- Real-time packet sniffing with detailed output
- Custom BPF (Berkeley Packet Filter) support for targeted captures
- Packet session storage and replay inspection
- Signal handling for graceful interruption (Ctrl+C)

### Packet Analysis
- Source and destination MAC addresses
- IP addresses and protocol identification
- Port numbers and service detection
- Protocol-specific fields (TTL, flags, sequence numbers, etc.)
- Payload inspection with hexadecimal and ASCII display
- Application-layer protocol identification

## Project Structure

```
C-Shark/
├── include/              # Header files
│   ├── arp.h            # ARP protocol handler declarations
│   ├── cshark.h         # Main application interfaces
│   ├── ipv4.h           # IPv4 protocol handler declarations
│   ├── ipv6.h           # IPv6 protocol handler declarations
│   └── sniffer.h        # Packet capture and analysis declarations
├── src/                 # Source files
│   ├── arp.c            # ARP packet processing
│   ├── cshark.c         # Main application and interface management
│   ├── ipv4.c           # IPv4 packet processing
│   ├── ipv6.c           # IPv6 packet processing
│   └── sniffer.c        # Core packet capture and protocol analysis
├── obj/                 # Object files (generated during build)
├── Makefile            # Build configuration
└── README.md           # Project documentation
```

## Requirements

### System Dependencies
- Linux operating system
- libpcap development library
- GCC compiler
- Root/sudo privileges (required for packet capture)

### Installing Dependencies

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install libpcap-dev gcc make
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install libpcap-devel gcc make
```

**Arch Linux:**
```bash
sudo pacman -S libpcap gcc make
```

## Building

Clone the repository and build the project:

```bash
git clone <repository-url>
cd C-Shark
make
```

To clean build artifacts:

```bash
make clean
```

## Usage

### Running C-Shark

C-Shark requires root privileges to capture packets:

```bash
sudo ./cshark
```

### Interactive Menu

Upon launch, C-Shark will:
1. Display available network interfaces
2. Prompt you to select an interface
3. Present a menu with capture options

**Menu Options:**
- **1. Start Sniffing (All Packets)** - Capture all network traffic
- **2. Start Sniffing (With Filters)** - Apply BPF filters for targeted capture
- **3. Inspect Last Session** - Review previously captured packets
- **4. Exit C-Shark** - Quit the application

### Using Filters

When selecting option 2, you can apply BPF filters such as:

```
tcp port 80                # Capture HTTP traffic
udp port 53                # Capture DNS queries
host 192.168.1.1          # Capture traffic to/from specific host
icmp                       # Capture ICMP packets
tcp and port 443          # Capture HTTPS traffic
```

### Stopping Capture

Press `Ctrl+C` during packet capture to stop and return to the menu.

## Example Output

```
[C-Shark] The Command-Line Packet Predator
==============================================
[C-Shark] Searching for available interfaces... Found!
 1. eth0 (Ethernet)
 2. wlan0 (Wireless)
 3. lo (Loopback)

Select an interface to sniff (1-3): 1

[C-Shark] Interface 'eth0' selected. What's next?

1. Start Sniffing (All Packets)
2. Start Sniffing (With Filters)
3. Inspect Last Session
4. Exit C-Shark

Enter choice (1-4): 1

========================================
Packet #1 | Length: 74 bytes | Timestamp: 2026-01-17 15:23:45
========================================
EtherType: IPv4 (0x0800)
Src MAC: aa:bb:cc:dd:ee:ff | Dst MAC: 11:22:33:44:55:66
Src IP: 192.168.1.100 | Dst IP: 142.250.185.46 | Protocol: TCP (6)
TTL: 64
ID: 0x4A2F | Total Length: 60 | Header Length: 20 bytes
Src Port: 54321 | Dst Port: 443 (HTTPS) | Seq: 1234567890 | Ack: 987654321
Flags: [SYN, ACK] | Window Size: 65535
```

## Technical Details

### Architecture

C-Shark follows a modular architecture:
- **cshark.c**: Entry point, interface management, and user interaction
- **sniffer.c**: Core packet capture loop, protocol demultiplexing, and session management
- **ipv4.c/ipv6.c**: Network layer protocol parsing
- **arp.c**: ARP protocol handler
- **Protocol handlers**: Decapsulation and field extraction for each protocol layer

### Packet Storage

Captured packets are stored in memory (up to 10,000 packets per session) and can be inspected after capture ends. Each stored packet includes:
- Complete packet data
- Capture timestamp
- Packet length

### Protocol Detection

C-Shark identifies protocols at multiple layers:
- **Ethernet**: EtherType field (0x0800 for IPv4, 0x86DD for IPv6, 0x0806 for ARP)
- **IP**: Protocol field (6 for TCP, 17 for UDP)
- **Transport**: Port numbers for application protocol identification

## Limitations

- Maximum 10,000 packets per capture session
- Memory-only storage (packets not persisted to disk)
- IPv4 and IPv6 only (no exotic Layer 3 protocols)
- Basic application protocol detection (port-based heuristics)
- No packet injection or modification capabilities

## Troubleshooting

### Permission Denied
```
Error: You don't have permission to capture on device
```
Solution: Run with sudo privileges.

### No Interfaces Found
```
[C-Shark] No interfaces found.
```
Solution: Ensure libpcap is properly installed and you have necessary permissions.

### Compilation Errors
If you encounter missing header errors, ensure libpcap-dev is installed:
```bash
sudo apt-get install libpcap-dev
```

## Contributing

Contributions are welcome. Please ensure code follows the existing structure:
- Headers in `include/`
- Source files in `src/`
- Use relative includes (`../include/header.h`)

## License

This project is provided as-is for educational purposes.

## Acknowledgments

Built using:
- libpcap for packet capture
- Standard C library and POSIX APIs
- Berkeley Packet Filter (BPF) syntax for filtering
