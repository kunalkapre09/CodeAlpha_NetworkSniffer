from scapy.all import sniff, IP, TCP, UDP, Raw, conf
from datetime import datetime
import os
import sys

LOG_FILE    = "captured_packets.log"
MAX_PACKETS = 50
SHOW_PAYLOAD = True

PROTOCOL_MAP = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
}

BANNER = """
╔══════════════════════════════════════════════════════════╗
║        🔍  CodeAlpha — Basic Network Sniffer             ║
║        Capturing live network packets...                 ║
║        Press  Ctrl+C  to stop                            ║
╚══════════════════════════════════════════════════════════╝
"""

packet_count = 0


def get_protocol_name(proto_num):
    return PROTOCOL_MAP.get(proto_num, f"OTHER({proto_num})")


def format_payload(raw_data):
    trimmed   = raw_data[:64]
    hex_part  = " ".join(f"{b:02X}" for b in trimmed)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in trimmed)
    suffix    = f"  ... (+{len(raw_data) - 64} more bytes)" if len(raw_data) > 64 else ""
    return f"HEX  : {hex_part}{suffix}\n          ASCII: {ascii_part}"


def process_packet(packet):
    global packet_count

    if not packet.haslayer(IP):
        return

    packet_count += 1
    timestamp  = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    ip_layer   = packet[IP]
    src_ip     = ip_layer.src
    dst_ip     = ip_layer.dst
    proto_name = get_protocol_name(ip_layer.proto)

    src_port = dst_port = flags = "-"

    if packet.haslayer(TCP):
        tcp      = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        flag_map = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}
        flags    = " | ".join(v for k, v in flag_map.items() if k in str(tcp.flags)) or str(tcp.flags)

    elif packet.haslayer(UDP):
        udp      = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport

    payload_str = ""
    if SHOW_PAYLOAD and packet.haslayer(Raw):
        payload_str = format_payload(bytes(packet[Raw].load))

    divider = "─" * 62
    lines = [
        f"\n{divider}",
        f"  Packet #{packet_count:04d}  [{timestamp}]",
        f"{divider}",
        f"  Protocol   : {proto_name}",
        f"  Source     : {src_ip}:{src_port}",
        f"  Destination: {dst_ip}:{dst_port}",
    ]

    if flags != "-":
        lines.append(f"  TCP Flags  : {flags}")

    if payload_str:
        lines.append(f"  Payload    :")
        lines.append(f"          {payload_str}")

    block = "\n".join(lines)
    print(block)

    with open(LOG_FILE, "a") as f:
        f.write(block + "\n")


def start_sniffing(interface=None, count=MAX_PACKETS):
    print(BANNER)
    print(f"  [*] Interface  : {interface if interface else 'Default (auto-detected)'}")
    print(f"  [*] Max Packets: {'Unlimited' if count == 0 else count}")
    print(f"  [*] Log File   : {os.path.abspath(LOG_FILE)}\n")

    with open(LOG_FILE, "w") as f:
        f.write(f"=== Network Sniffer Log — {datetime.now()} ===\n\n")

    try:
        sniff(iface=interface, prn=process_packet, count=count, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n  [!] ERROR: Run this script with admin/root privileges.")
        print("      Windows → Run CMD as Administrator")
        print("      Linux   → sudo python3 network_sniffer.py")
        sys.exit(1)

    print(f"\n\n  ✅ Done! Captured {packet_count} packets.")
    print(f"  📄 Log saved → {os.path.abspath(LOG_FILE)}")


if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    conf.verb = 0
    start_sniffing(interface=iface, count=MAX_PACKETS)
