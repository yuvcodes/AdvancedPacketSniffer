import socket
import struct
import argparse
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMPv6EchoRequest, ICMPv6EchoReply, conf

# Argument parser for optional features
parser = argparse.ArgumentParser(description="Advanced Packet Sniffer with DNS Resolution")
parser.add_argument("--resolve", action="store_true", help="Resolve IP addresses to hostnames")
args = parser.parse_args()

def resolve_ip(ip_address):
    """Resolve an IP address to a hostname if --resolve is enabled."""
    if args.resolve:
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return f"{hostname} ({ip_address})"
        except socket.herror:
            return ip_address
    return ip_address

def unpack_ipv6(data):
    """Unpack IPv6 packet."""
    ipv6_header = struct.unpack('!IHBB16s16s', data[:40])
    version = (ipv6_header[0] >> 28)
    traffic_class = (ipv6_header[0] >> 20) & 0xFF
    flow_label = ipv6_header[0] & 0xFFFFF
    payload_length = ipv6_header[1]
    next_header = ipv6_header[2]
    hop_limit = ipv6_header[3]

    src_ip = resolve_ip(socket.inet_ntop(socket.AF_INET6, ipv6_header[4]))
    dest_ip = resolve_ip(socket.inet_ntop(socket.AF_INET6, ipv6_header[5]))

    return version, traffic_class, flow_label, payload_length, next_header, hop_limit, src_ip, dest_ip, data[40:]

def unpack_tcp(data):
    """Unpack TCP segment."""
    tcp_header = struct.unpack('!HHIIBBHHH', data[:20])
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = tcp_header[:5]
    offset = (offset_reserved_flags >> 4) * 4
    flags = tcp_header[4] & 0b00111111
    urg, ack, psh, rst, syn, fin = [(flags >> i) & 1 for i in range(6)]

    return src_port, dest_port, sequence, acknowledgment, urg, ack, psh, rst, syn, fin, data[offset:]

def unpack_udp(data):
    """Unpack UDP segment."""
    udp_header = struct.unpack('!HHHH', data[:8])
    src_port, dest_port, length, checksum = udp_header
    return src_port, dest_port, length, checksum, data[8:]

def unpack_icmpv6(data):
    """Unpack ICMPv6 packet."""
    icmpv6_header = struct.unpack('!BBH', data[:4])
    icmpv6_type, code, checksum = icmpv6_header
    return icmpv6_type, code, checksum, data[4:]

def packet_callback(packet):
    """Process captured packets and display structured information."""
    if Ether in packet:
        dest_mac = packet[Ether].dst.upper()
        src_mac = packet[Ether].src.upper()
        eth_proto = packet[Ether].type

        print("\nEthernet Frame:")
        print(f"  - Destination: {dest_mac}")
        print(f"  - Source: {src_mac}")
        print(f"  - Protocol: {eth_proto}")

        # IPv4 Packet
        if IP in packet:
            src_ip = resolve_ip(packet[IP].src)
            dest_ip = resolve_ip(packet[IP].dst)
            print("  - IPv4 Packet:")
            print(f"    - Source: {src_ip}")
            print(f"    - Destination: {dest_ip}")

            if packet[IP].proto == 6 and TCP in packet:  # TCP
                src_port, dest_port, sequence, acknowledgment, urg, ack, psh, rst, syn, fin, tcp_data = unpack_tcp(bytes(packet[TCP]))
                print(f"    - TCP Segment: {src_port} -> {dest_port}")
                print(f"      - Flags: [URG: {urg}, ACK: {ack}, PSH: {psh}, RST: {rst}, SYN: {syn}, FIN: {fin}]")
                print(f"      - Data: {tcp_data.hex()}")

            elif packet[IP].proto == 17 and UDP in packet:  # UDP
                src_port, dest_port, length, checksum, udp_data = unpack_udp(bytes(packet[UDP]))
                print(f"    - UDP Segment: {src_port} -> {dest_port}")
                print(f"      - Length: {length}, Checksum: {checksum}")
                print(f"      - Data: {udp_data.hex()}")

        # IPv6 Packet
        elif IPv6 in packet:
            version, traffic_class, flow_label, payload_length, next_header, hop_limit, src_ip, dest_ip, data = unpack_ipv6(bytes(packet[IPv6]))
            print("  - IPv6 Packet:")
            print(f"    - Version: {version}, Traffic Class: {traffic_class}, Flow Label: {flow_label}")
            print(f"    - Next Header: {next_header}, Hop Limit: {hop_limit}")
            print(f"    - Source: {src_ip}")
            print(f"    - Destination: {dest_ip}")

            if next_header == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, urg, ack, psh, rst, syn, fin, tcp_data = unpack_tcp(data)
                print(f"    - TCP Segment: {src_port} -> {dest_port}")
                print(f"      - Flags: [URG: {urg}, ACK: {ack}, PSH: {psh}, RST: {rst}, SYN: {syn}, FIN: {fin}]")
                print(f"      - Data: {tcp_data.hex()}")

            elif next_header == 17:  # UDP
                src_port, dest_port, length, checksum, udp_data = unpack_udp(data)
                print(f"    - UDP Segment: {src_port} -> {dest_port}")
                print(f"      - Length: {length}, Checksum: {checksum}")
                print(f"      - Data: {udp_data.hex()}")

            elif next_header == 58:  # ICMPv6
                icmpv6_type, code, checksum, icmpv6_data = unpack_icmpv6(data)
                print("    - ICMPv6 Packet:")
                print(f"      - Type: {icmpv6_type}, Code: {code}, Checksum: {checksum}")
                print(f"      - Data: {icmpv6_data.hex()}")

def main():
    """Start packet sniffing."""
    active_iface = conf.iface
    print(f"Starting packet capture on: {active_iface}...\n")
    sniff(iface=active_iface, prn=packet_callback, store=False)

if __name__ == "__main__":
    main()