# 🔍 Basic Network Sniffer — CodeAlpha Cybersecurity Internship Task 1

A Python-based network packet sniffer built using **Scapy** that captures live network traffic and displays key packet information including source/destination IPs, protocols, ports, TCP flags, and raw payloads.

---

## 📌 Features

- ✅ Captures live TCP, UDP, and ICMP packets
- ✅ Displays Source & Destination IP addresses and Ports
- ✅ Shows Protocol type (TCP / UDP / ICMP)
- ✅ Decodes TCP Flags (SYN, ACK, FIN, RST, PSH, URG)
- ✅ Shows raw payload in HEX + ASCII format
- ✅ Saves all captured packets to a `.log` file
- ✅ Supports custom network interface selection
- ✅ Configurable packet capture limit

---

## 🛠 Requirements

- Python 3.7+
- Scapy library

### Install dependencies:
```bash
pip install scapy
```

> **Windows users** may also need: [Npcap](https://npcap.com/#download) — install with "WinPcap API-compatible mode" checked.

---

## ▶️ How to Run

> ⚠️ **Requires Administrator / Root privileges** to capture raw packets.

### Windows (Run CMD as Administrator):
```bash
python network_sniffer.py
```

### Linux / macOS:
```bash
sudo python3 network_sniffer.py
```

### Capture on a specific interface:
```bash
sudo python3 network_sniffer.py eth0
```

---

## ⚙️ Configuration (inside the script)

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_PACKETS` | `50` | Number of packets to capture (0 = unlimited) |
| `SHOW_PAYLOAD` | `True` | Show raw payload data |
| `LOG_FILE` | `captured_packets.log` | Output log file name |

---

## 📄 Sample Output

```
╔══════════════════════════════════════════════════════════╗
║        🔍  CodeAlpha — Basic Network Sniffer             ║
║        Capturing live network packets...                 ║
║        Press  Ctrl+C  to stop                            ║
╚══════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────────
  Packet #0001  [14:32:05.412]
──────────────────────────────────────────────────────────────
  Protocol   : TCP
  Source     : 192.168.1.5:52341
  Destination: 142.250.195.46:443
  TCP Flags  : ACK
  Payload    :
          HEX  : 47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31
          ASCII: GET / HTTP/1.1
```

---

## 📁 Project Structure

```
CodeAlpha_NetworkSniffer/
│
├── network_sniffer.py      # Main Python script
├── captured_packets.log    # Auto-generated log file (after running)
└── README.md               # Project documentation
```

---

## 🔐 Legal & Ethical Note

> This tool is intended for **educational purposes only**. Only use it on networks you own or have **explicit permission** to monitor. Unauthorized packet sniffing is illegal under computer crime laws in most countries.

---

## 👨‍💻 Author

**[Your Name]**  
CodeAlpha Cybersecurity Internship  
GitHub: [your-github-username]  
LinkedIn: [your-linkedin-profile]

---

## 🏷️ Tags

`python` `cybersecurity` `network-sniffer` `scapy` `packet-capture` `codealpha` `internship`
