import socket
import struct


def format_mac(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)


def get_sni_from_tls(data):
    try:
        # Skip record header
        pointer = 0

        content_type = data[pointer]
        if content_type != 22:  # 22 = handshake
            return None
        pointer += 5

        # Handshake header
        if data[pointer] != 1:  # 1 = ClientHello
            return None
        pointer += 4

        # Skip random + session ID
        pointer += 34

        # Skip cipher suites
        cs_len = struct.unpack('!H', data[pointer:pointer+2])[0]
        pointer += 2 + cs_len

        # Skip compression methods
        comp_len = data[pointer]
        pointer += 1 + comp_len

        # Extensions length
        ext_len = struct.unpack('!H', data[pointer:pointer+2])[0]
        pointer += 2

        end = pointer + ext_len

        # Loop extensions
        while pointer + 4 <= end:
            ext_type = struct.unpack('!H', data[pointer:pointer+2])[0]
            ext_size = struct.unpack('!H', data[pointer+2:pointer+4])[0]
            pointer += 4

            # SNI = extension 0
            if ext_type == 0:
                # Skip list length + type
                server_name_len = struct.unpack(
                    '!H', data[pointer+3:pointer+5]
                )[0]
                server_name = data[pointer+5:pointer+5+server_name_len]
                return server_name.decode('utf-8', errors='ignore')

            pointer += ext_size

    except Exception:
        return None


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Listening for packets... Press Ctrl+C to stop.\n")

    while True:
        raw_data, addr = conn.recvfrom(65535)

        # ---------------- Ethernet ----------------
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        proto = socket.htons(proto)

        # 0x0800 == IPv4
        if proto == 8:

            # ---------------- IPv4 ----------------
            version_header_length = raw_data[14]
            header_length = (version_header_length & 15) * 4

            ttl, ip_proto, src, target = struct.unpack(
                '! 8x B B 2x 4s 4s', raw_data[14:34]
            )

            src_ip = socket.inet_ntoa(src)
            dest_ip = socket.inet_ntoa(target)

            transport = raw_data[14 + header_length:]

            # ---------------- TCP ----------------
            if ip_proto == 6 and len(transport) >= 14:
                src_port, dest_port, sequence, ack, offset_reserved_flags = \
                    struct.unpack('! H H L L H', transport[:14])

                offset = (offset_reserved_flags >> 12) * 4
                payload = transport[offset:]

                print(f"[TCP] {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

                # HTTP Detection
                if src_port in (80, 8080) or dest_port in (80, 8080):
                    if payload.startswith(b"GET") or payload.startswith(b"POST"):
                        try:
                            line = payload.split(b"\r\n")[0].decode()
                            print(f"   [HTTP] {line}")
                        except:
                            pass

                # TLS ClientHello
                if src_port == 443 or dest_port == 443:
                    sni = get_sni_from_tls(payload)
                    if sni:
                        print(f"   [TLS] SNI = {sni}")

            # ---------------- UDP ----------------
            elif ip_proto == 17 and len(transport) >= 8:
                src_port, dest_port, size = struct.unpack(
                    '! H H 2x H', transport[:8]
                )
                payload = transport[8:]

                print(f"[UDP] {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

                # DNS detection
                if src_port == 53 or dest_port == 53:
                    try:
                        qdcount = struct.unpack('!H', payload[4:6])[0]
                        pointer = 12
                        domain_parts = []

                        while True:
                            length = payload[pointer]
                            if length == 0:
                                break
                            pointer += 1
                            domain_parts.append(
                                payload[pointer:pointer+length].decode()
                            )
                            pointer += length

                        domain = ".".join(domain_parts)
                        print(f"   [DNS] Query = {domain}")
                    except Exception:
                        pass


if __name__ == "__main__":
    main()


