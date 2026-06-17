from dataclasses import dataclass
from typing import Optional

from src.models.enums import Protocol


@dataclass(slots=True)
class RawPacket:
    """
    Packet exactly as read from a PCAP file.
    No parsing has been performed yet.
    """

    timestamp: float
    length: int
    data: bytes


@dataclass(slots=True)
class ParsedPacket:
    """
    Packet after protocol parsing.
    Contains structured networking information.
    """

    timestamp: float

    src_ip: str
    dst_ip: str

    src_port: Optional[int]
    dst_port: Optional[int]

    protocol: Protocol

    payload: bytes

    packet_size: int