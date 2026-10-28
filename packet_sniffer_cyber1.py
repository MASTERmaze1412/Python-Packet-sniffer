"""
Packet Sniffer + IP Spoofing + Network Scanner
, menu-driven tool.

Requires (pip install scapy)
 - keyboard (pip install keyboard) [or modify as needed]
Run as root/admin for raw sockets and ARP scanning.
"""

import socket
import struct
import threading
import time
import textwrap
#import keyboard
from scapy.all import IP, TCP as ScapyTCP, UDP as ScapyUDP, send, ARP, Ether, srp

# === Helpers ===
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    return ':'.join(byte_str).upper()

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# === Protocol Classes ===
class Ethernet:
    def __init__(self, raw_data):
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]

class IPv4:
    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

class ICMP:
    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]

class TCP:
    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]

class UDP:
    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', raw_data[:8])
        self.data = raw_data[8:]

class HTTP:
    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data

# === PCAP Writer ===
class Pcap:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()

    def write_global_header(self):
        self.file.write(
            b'\xd4\xc3\xb2\xa1' +      # magic number
            b'\x02\x00' +              # major version
            b'\x04\x00' +              # minor version
            b'\x00\x00\x00\x00' +      # thiszone
            b'\x00\x00\x00\x00' +      # sigfigs
            b'\xff\xff\x00\x00' +      # snaplen
            b'\x01\x00\x00\x00'        # network = Ethernet
        )

    def write(self, packet_data):
        ts_sec = int(time.time())
        ts_usec = int((time.time() - ts_sec) * 1_000_000)
        length = len(packet_data)
        packet_header = struct.pack('<IIII', ts_sec, ts_usec, length, length)
        self.file.write(packet_header)
        self.file.write(packet_data)

    def close(self):
        self.file.close()

# === Constants ===
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
DATA_TAB_3 = '\t\t\t   '

# === Globals ===
sniffing = False
captured_packets = []
pcap_writer = None

# === Sniffer ===
def sniff():
    global sniffing, captured_packets, pcap_writer
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("Error: Run this program as root/administrator.")
        sniffing = False
        return

    print("[*] Sniffing started. Press 'q' to stop...\n")
    while sniffing:
        try:
            raw_data, addr = conn.recvfrom(65535)
            if pcap_writer:
                pcap_writer.write(raw_data)
            captured_packets.append(raw_data)

            eth = Ethernet(raw_data)
            print('\nEthernet Frame:')
            print(TAB_1 + f'Destination: {eth.dest_mac}, Source: {eth.src_mac}, Protocol: {eth.proto}')

            if eth.proto == 8:
                ipv4 = IPv4(eth.data)
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + f'Version: {ipv4.version}, Header Length: {ipv4.header_length}, TTL: {ipv4.ttl},')
                print(TAB_2 + f'Protocol: {ipv4.proto}, Source: {ipv4.src}, Target: {ipv4.target}')

                if ipv4.proto == 1:
                    icmp = ICMP(ipv4.data)
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + f'Type: {icmp.type}, Code: {icmp.code}, Checksum: {icmp.checksum},')
                    print(TAB_2 + 'ICMP Data:')
                    print(format_multi_line(DATA_TAB_3, icmp.data))

                elif ipv4.proto == 6:
                    tcp = TCP(ipv4.data)
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + f'Source Port: {tcp.src_port}, Destination Port: {tcp.dest_port}')
                    print(TAB_2 + f'Sequence: {tcp.sequence}, Acknowledgment: {tcp.acknowledgment}')
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + f'URG: {tcp.flag_urg}, ACK: {tcp.flag_ack}, PSH: {tcp.flag_psh}')
                    print(TAB_3 + f'RST: {tcp.flag_rst}, SYN: {tcp.flag_syn}, FIN:{tcp.flag_fin}')

                    if len(tcp.data) > 0:
                        if tcp.src_port == 80 or tcp.dest_port == 80:
                            print(TAB_2 + 'HTTP Data:')
                            try:
                                http = HTTP(tcp.data)
                                for line in str(http.data).split('\n'):
                                    print(DATA_TAB_3 + line)
                            except:
                                print(format_multi_line(DATA_TAB_3, tcp.data))
                        else:
                            print(TAB_2 + 'TCP Data:')
                            print(format_multi_line(DATA_TAB_3, tcp.data))

                elif ipv4.proto == 17:
                    udp = UDP(ipv4.data)
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + f'Source Port: {udp.src_port}, Destination Port: {udp.dest_port}, Length: {udp.size}')

                else:
                    print(TAB_1 + 'Other IPv4 Data:')
                    print(format_multi_line(DATA_TAB_3, ipv4.data))
            else:
                print('Ethernet Data:')
                print(format_multi_line(DATA_TAB_3, eth.data))

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] Error while sniffing packet: {e}")

    print("\n[*] Sniffing stopped.")

def start_sniffing():
    global sniffing
    sniffing = True
    thread = threading.Thread(target=sniff, daemon=True)
    thread.start()
#    keyboard.wait('q')
    input('enter to stop')
    stop_sniffing()

def stop_sniffing():
    global sniffing
    sniffing = False

def save_packets_to_file():
    global captured_packets
    filename = input("Enter filename to save packets (e.g., capture.pcap): ").strip()
    if not filename:
        print("Invalid filename.")
        return
    try:
        with open(filename, 'wb') as f:
            f.write(
                b'\xd4\xc3\xb2\xa1' +
                b'\x02\x00' +
                b'\x04\x00' +
                b'\x00\x00\x00\x00' +
                b'\x00\x00\x00\x00' +
                b'\xff\xff\x00\x00' +
                b'\x01\x00\x00\x00'
            )
            for pkt in captured_packets:
                ts_sec = int(time.time())
                ts_usec = int((time.time() - ts_sec) * 1_000_000)
                length = len(pkt)
                packet_header = struct.pack('<IIII', ts_sec, ts_usec, length, length)
                f.write(packet_header)
                f.write(pkt)
        print(f"[*] Packets saved to {filename}")
    except Exception as e:
        print(f"[!] Failed to save packets: {e}")

def forge_packet():
    print("\n=== Forge and Send Packet ===")
    src_ip = input("Enter spoofed source IP: ").strip()
    dst_ip = input("Enter destination IP: ").strip()
    proto = input("Enter protocol (tcp/udp): ").strip().lower()
    sport = input("Enter source port (default 12345): ").strip()
    dport = input("Enter destination port (default 80): ").strip()
    payload = input("Enter payload (leave blank for none): ")

    if not sport.isdigit():
        sport = 12345
    else:
        sport = int(sport)
    if not dport.isdigit():
        dport = 80
    else:
        dport = int(dport)

    try:
        ip_layer = IP(src=src_ip, dst=dst_ip)
        if proto == 'udp':
            packet = ip_layer / ScapyUDP(sport=sport, dport=dport) / payload
        else:
            packet = ip_layer / ScapyTCP(sport=sport, dport=dport) / payload

        print(f"[*] Sending spoofed {proto.upper()} packet from {src_ip}:{sport} to {dst_ip}:{dport}")
        send(packet, verbose=0)
        print("[*] Packet sent!")
    except Exception as e:
        print(f"[!] Failed to send spoofed packet: {e}")

def scan_network():
    ip_range = input("Enter IP range to scan (e.g., 192.168.1.1/24): ").strip()
    if not ip_range:
        print("Invalid IP range.")
        return

    print(f"Scanning {ip_range} for active devices...")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    print(f"\nFound {len(devices)} active devices:")
    for device in devices:
        print(f"IP: {device['ip']}  MAC: {device['mac']}")

# === Menu ===
def menu():
    global pcap_writer
    while True:
        print("\n=== Packet Sniffer Menu ===")
        print("1. Start Sniffing (press 'q' to stop)")
        print("2. Save Captured Packets to File")
        print("3. Forge and Send Packet (IP Spoofing)")
        print("4. Scan for active devices nearby")
        print("5. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            pcap_filename = input("Enter PCAP filename to save live capture (or leave blank to skip saving): ").strip()
            if pcap_filename:
                try:
                    pcap_writer = Pcap(pcap_filename)
                    print(f"[*] Live capture saving to {pcap_filename}")
                except Exception as e:
                    print(f"[!] Could not open pcap file for writing: {e}")
                    pcap_writer = None
            else:
                pcap_writer = None

            start_sniffing()
            if pcap_writer:
                pcap_writer.close()
                pcap_writer = None

        elif choice == '2':
            save_packets_to_file()

        elif choice == '3':
            forge_packet()

        elif choice == '4':
            scan_network()

        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    menu()
