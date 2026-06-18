from src.core.classifier import Classifier
from src.core.flow_tracker import FlowTracker
from src.core.http_extractor import HTTPExtractor
from src.core.packet_parser import PacketParser
from src.core.pcap_reader import PcapReader
from src.core.pcap_writer import PcapWriter
from src.core.rule_manager import RuleManager
from src.core.sni_extractor import SNIExtractor
from src.core.statistics import Statistics
from src.models.enums import Action, AppType
from src.models.packet import RawPacket


class DpiEngine:
    """
    Runs the packet inspection pipeline.
    """

    def __init__(self, rule_manager: RuleManager | None = None):
        self.parser = PacketParser()
        self.flow_tracker = FlowTracker()
        self.sni_extractor = SNIExtractor()
        self.http_extractor = HTTPExtractor()
        self.classifier = Classifier()
        self.rule_manager = rule_manager or RuleManager()
        self.stats = Statistics()

    def process_packet(self, raw_packet: RawPacket) -> Action:
        """
        Process one packet and return the policy decision.
        """
        try:
            packet = self.parser.parse(raw_packet)
            if not packet:
                self.stats.add_decision(Action.FORWARD)
                return Action.FORWARD

            print("+", end="", flush=True)
            self.stats.add_packet(packet.packet_size)

            existing_flow_count = self.flow_tracker.get_flow_count()
            flow = self.flow_tracker.add_packet(packet)
            is_new_flow = self.flow_tracker.get_flow_count() > existing_flow_count
            if flow.blocked:
                self.stats.add_decision(Action.DROP, app_type=flow.app_type, domain=flow.sni)
                return Action.DROP

            domain = self.sni_extractor.extract(packet.payload)
            if not domain:
                domain = self.http_extractor.extract_host(packet.payload)

            classification_text = domain
            if not classification_text:
                classification_text = packet.payload.decode("utf-8", errors="ignore")

            app_type = self.classifier.classify(classification_text)
            action = self.rule_manager.evaluate(
                app_type=app_type,
                domain=domain,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
            )
            self.stats.add_decision(action, app_type=app_type, domain=domain)

            flow.app_type = app_type
            flow.sni = domain or flow.sni
            if action == Action.DROP:
                flow.blocked = True
            if is_new_flow:
                self.stats.add_flow(app_type)

            if app_type != AppType.UNKNOWN:
                label = domain or app_type.value
                print(f"\n[DETECTED] {label} -> {app_type.value} -> {action.value}")

            return action

        except Exception as exc:
            print(f"\n[PIPELINE CRASH]: {exc}")
            self.stats.add_decision(Action.FORWARD)
            return Action.FORWARD

    def process_pcap(self, input_path: str, output_path: str):
        """
        Read an input PCAP and write only forwarded packets to the output PCAP.
        """
        reader = PcapReader(input_path)
        linktype = reader.get_linktype()

        with PcapWriter(output_path, linktype) as writer:
            for raw_packet in reader.read_packets():
                self.stats.add_raw_packet()
                print(".", end="", flush=True)
                action = self.process_packet(raw_packet)

                if action == Action.DROP:
                    continue

                writer.write_packet(raw_packet)

        print(f"\n[*] Filtered PCAP written to: {output_path}")
        print(self.stats.generate_report())

    def process_live_scapy_packet(self, scapy_packet):
        """
        Process one packet captured by Scapy.
        """
        if not scapy_packet.haslayer("IP"):
            return

        from scapy.all import raw

        print(".", end="", flush=True)
        raw_bytes = raw(scapy_packet)
        timestamp = float(getattr(scapy_packet, "time", 0))

        self.stats.add_raw_packet()
        self.process_packet(
            RawPacket(
                timestamp=timestamp,
                data=raw_bytes,
                length=len(raw_bytes),
            )
        )

    def report(self) -> str:
        return self.stats.generate_report()
