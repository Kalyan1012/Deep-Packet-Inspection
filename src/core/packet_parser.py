from src.models.packet import ParsedPacket, RawPacket
from src.models.enums import Protocol


class PacketParser:
    """
    SAFE MODE PARSER (for debugging + pipeline validation)
    """

    @staticmethod
    def parse(raw_packet: RawPacket) -> ParsedPacket | None:
        try:
            data = raw_packet.data

            if not data:
                return None

            # fake but stable fields
            return ParsedPacket(
                timestamp=raw_packet.timestamp,
                src_ip="192.168.1.10",
                dst_ip="172.217.0.1",
                src_port=12345,
                dst_port=443,
                protocol=Protocol.TCP,
                payload=data,
                packet_size=len(data),
            )

        except Exception as e:
            print("Parser error:", e)
            return None