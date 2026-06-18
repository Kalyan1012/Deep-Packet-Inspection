from src.models.flow import Flow
from src.models.flow import FlowKey
from src.models.packet import ParsedPacket


class FlowTracker:
    """
    Tracks network flows using the 5-tuple.
    """

    def __init__(self):
        self.flows: dict[FlowKey, Flow] = {}

    def process_packet(self, packet: ParsedPacket) -> Flow:
        """
        Create or update a flow from a parsed packet.
        """
        flow_key = FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port or 0,
            dst_port=packet.dst_port or 0,
            protocol=packet.protocol,
        )

        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(key=flow_key)

        flow = self.flows[flow_key]

        flow.packet_count += 1
        flow.byte_count += packet.packet_size

        return flow

    # 🌟 ADD THIS METHOD BELOW TO FIX THE MAIN.PY CRASH
    def add_packet(self, packet: ParsedPacket) -> Flow:
        """
        Wrapper method to match the main.py API pipeline expectation.
        """
        return self.process_packet(packet)

    def get_flow_count(self) -> int:
        """
        Return total number of tracked flows.
        """
        return len(self.flows)