import socket

import dpkt

from src.core.dpi_engine import DpiEngine
from src.models.enums import Action
from src.models.packet import RawPacket


def build_raw_http_packet(payload: bytes) -> RawPacket:
    tcp = dpkt.tcp.TCP(sport=12345, dport=80, seq=1, data=payload)
    ip = dpkt.ip.IP(
        src=socket.inet_aton("192.168.1.10"),
        dst=socket.inet_aton("157.240.221.35"),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=tcp,
    )

    data = bytes(ip)
    return RawPacket(timestamp=1.0, length=len(data), data=data)


def test_engine_drops_facebook_http_packet():
    engine = DpiEngine()
    packet = build_raw_http_packet(
        b"GET / HTTP/1.1\r\nHost: www.facebook.com\r\n\r\n"
    )

    assert engine.process_packet(packet) == Action.DROP


def test_engine_drops_later_packets_in_blocked_flow():
    engine = DpiEngine()
    first_packet = build_raw_http_packet(
        b"GET / HTTP/1.1\r\nHost: www.facebook.com\r\n\r\n"
    )
    later_packet = build_raw_http_packet(b"continued encrypted payload")

    assert engine.process_packet(first_packet) == Action.DROP
    assert engine.process_packet(later_packet) == Action.DROP
