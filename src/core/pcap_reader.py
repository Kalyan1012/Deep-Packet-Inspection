from pathlib import Path
from typing import Generator

import dpkt

from src.models.packet import RawPacket


class PcapReader:
    """
    Reads packets from a PCAP file
    and yields RawPacket objects.
    """

    def __init__(self, pcap_path: str):
        self.pcap_path = Path(pcap_path)

    def read_packets(self) -> Generator[RawPacket, None, None]:
        """
        Stream packets from a PCAP file.
        """

        with open(self.pcap_path, "rb") as file:
            pcap = dpkt.pcap.Reader(file)

            for timestamp, buffer in pcap:
                yield RawPacket(
                    timestamp=timestamp,
                    length=len(buffer),
                    data=buffer,
                )