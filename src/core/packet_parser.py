import socket

import dpkt

from src.models.enums import Protocol
from src.models.packet import ParsedPacket
from src.models.packet import RawPacket


class PacketParser:
    """
    Converts RawPacket into ParsedPacket.
    """

    @staticmethod
    def parse(raw_packet: RawPacket) -> ParsedPacket | None:
        try:
            eth = dpkt.ethernet.Ethernet(raw_packet.data)

            if not isinstance(eth.data, dpkt.ip.IP):
                return None

            ip = eth.data

            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            protocol = Protocol.UNKNOWN

            src_port = None
            dst_port = None

            payload = b""

            if isinstance(ip.data, dpkt.tcp.TCP):
                protocol = Protocol.TCP

                src_port = ip.data.sport
                dst_port = ip.data.dport

                payload = bytes(ip.data.data)

            elif isinstance(ip.data, dpkt.udp.UDP):
                protocol = Protocol.UDP

                src_port = ip.data.sport
                dst_port = ip.data.dport

                payload = bytes(ip.data.data)

            return ParsedPacket(
                timestamp=raw_packet.timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                payload=payload,
                packet_size=raw_packet.length,
            )

        except Exception:
            return None