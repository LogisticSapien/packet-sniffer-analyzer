import socket
import struct


def format_mac(bytes_addr):
    """Convert raw bytes to human-readable MAC address."""
    return ':'.join(format(b, '02x') for b in bytes_addr)


def main():
    # Create raw socket (Linux/macOS). Windows requires admin + Npcap.
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Listening for packets... Press Ctrl+C to stop.\n")

    while True:
        raw_data, addr = conn.recvfrom(65535)

        # -------- Ethernet --------
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        dest_mac = format_mac(dest_mac)
        src_mac = format_mac(src_mac)
        proto = socket.htons(proto)

        # IPv4 = 0x0800 = 8 after htons conversion
        if proto == 8:
            version_header_length = raw_data[14]
            header_length = (version_header_length & 15) * 4

            ttl, ip_proto, src, target = struct.unpack(
                '! 8x B B 2x 4s 4s',
                raw_data[14:34]
            )

            src_ip = socket.inet_ntoa(src)
            dest_ip = socket.inet_ntoa(target)

            print(f"[IPv4] Src IP: {src_ip} -> Dest IP: {dest_ip}, Proto: {ip_proto}")


if __name__ == "__main__":
    main()

