import socket
import struct

def main():
    # Create raw socket (works on Linux/macOS; Windows requires admin)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Listening for packets... Press Ctrl+C to stop.\n")

    while True:
        raw_data, addr = conn.recvfrom(65535)

        # Ethernet header = first 14 bytes
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        dest_mac = format_mac(dest_mac)
        src_mac = format_mac(src_mac)
        proto = socket.htons(proto)

        print(f"Ethernet Frame -> Src: {src_mac}, Dest: {dest_mac}, Protocol: {proto}")

def format_mac(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)

if __name__ == "__main__":
    main()
