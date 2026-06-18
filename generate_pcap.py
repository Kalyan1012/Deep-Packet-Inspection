from pathlib import Path
import socket

import dpkt


def build_http_packet(dst_ip: str, host: str, path: str = "/") -> bytes:
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: dpi-test\r\n"
        "\r\n"
    ).encode("ascii")

    tcp = dpkt.tcp.TCP(sport=12345, dport=80, seq=1, data=payload)
    ip = dpkt.ip.IP(
        src=socket.inet_aton("192.168.1.10"),
        dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=tcp,
    )
    return bytes(ip)


def create_pcap():
    packets = [
        build_http_packet("142.250.190.78", "www.youtube.com"),
        build_http_packet("140.82.112.4", "github.com"),
        build_http_packet("157.240.221.35", "www.facebook.com"),
        build_http_packet("142.250.190.78", "www.google.com"),
    ]

    output_path = Path("pcaps/test.pcap")
    output_path.parent.mkdir(exist_ok=True)

    with open(output_path, "wb") as file:
        writer = dpkt.pcap.Writer(file, linktype=dpkt.pcap.DLT_RAW)
        for index, packet in enumerate(packets):
            writer.writepkt(packet, ts=float(index))

    print(f"[+] Sample PCAP created: {output_path}")


if __name__ == "__main__":
    create_pcap()
