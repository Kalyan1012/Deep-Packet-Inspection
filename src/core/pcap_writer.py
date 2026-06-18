from pathlib import Path

import dpkt

from src.models.packet import RawPacket


class PcapWriter:
    """
    Writes raw packets to a PCAP file.
    """

    def __init__(self, pcap_path: str, linktype: int):
        self.pcap_path = Path(pcap_path)
        self.linktype = linktype
        self.file = None
        self.writer = None

    def __enter__(self):
        self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(self.pcap_path, "wb")
        self.writer = dpkt.pcap.Writer(self.file, linktype=self.linktype)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.file:
            self.file.close()

    def write_packet(self, raw_packet: RawPacket):
        """
        Write one packet using its original timestamp.
        """
        self.writer.writepkt(raw_packet.data, ts=raw_packet.timestamp)
