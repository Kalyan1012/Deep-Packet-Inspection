import socket
import dpkt
from src.models.packet import ParsedPacket, RawPacket
from src.models.enums import Protocol

class PacketParser:
    """
    Real-Time DPI Decoder Engine
    Parses raw binary link-layer frames into structured network packets.
    """

    @staticmethod
    def parse(raw_packet: RawPacket) -> ParsedPacket | None:
        try:
            data = raw_packet.data
            if not data:
                return None

            # 1. Unpack Ethernet Frame Layer-2
            eth = dpkt.ethernet.Ethernet(data)
            
            # 2. Extract IP Layer-3 (Support only IPv4 for now)
            if not isinstance(eth.data, dpkt.ip.IP):
                return None
            
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            
            # 3. Extract Transport Layer-4 (TCP / UDP)
            protocol_enum = Protocol.UNKNOWN
            src_port = 0
            dst_port = 0
            payload = b""

            if isinstance(ip.data, dpkt.tcp.TCP):
                protocol_enum = Protocol.TCP
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                payload = tcp.data  # This holds your TLS Client Hello / HTTP payload!
                
            elif isinstance(ip.data, dpkt.udp.UDP):
                protocol_enum = Protocol.UDP
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                payload = udp.data

            # Drop packets without valid application payloads to maximize efficiency
            if not payload:
                return None

            return ParsedPacket(
                timestamp=raw_packet.timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_enum,
                payload=payload,
                packet_size=len(data),
            )

        except Exception as e:
            # Silently handle unparseable protocols (ARP, ICMP, IPv6, etc.)
            return None