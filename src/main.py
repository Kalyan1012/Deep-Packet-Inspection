from src.core.pcap_reader import PcapReader
from src.core.packet_parser import PacketParser
from src.core.flow_tracker import FlowTracker
from src.core.sni_extractor import SNIExtractor
from src.core.classifier import Classifier
from src.core.rule_engine import RuleEngine
from src.core.statistics import Statistics

from src.models import packet
from src.models.enums import Action, AppType
from src.models.rule import Rule


def build_rules():
    """
    Simple policy for now (we can later load from file)
    """
    return [
        Rule(app_type=AppType.YOUTUBE, action=Action.FORWARD, enabled=True),
        Rule(app_type=AppType.FACEBOOK, action=Action.DROP, enabled=True),
        Rule(app_type=AppType.GITHUB, action=Action.FORWARD, enabled=True),
    ]


def main(pcap_file: str):

    print("\n[*] Starting DPI Engine...\n")

    # -----------------------------
    # Initialize all components
    # -----------------------------
    reader = PcapReader(pcap_file)
    parser = PacketParser()
    flow_tracker = FlowTracker()
    sni_extractor = SNIExtractor()
    classifier = Classifier()
    stats = Statistics()
    rule_engine = RuleEngine(build_rules())

    # -----------------------------
    # MAIN PROCESSING LOOP
    # -----------------------------
    for raw_packet in reader.read_packets():

        # 1. Parse packet
        packet = parser.parse(raw_packet)
        print("DEBUG:", packet)

        if not packet:
            continue
        # 2. Update stats
        stats.add_packet(packet.packet_size)

        # 3. Add to flow tracker
        flow = flow_tracker.add_packet(packet)
        if not flow:
            continue

        # 4. Extract domain (SNI)
        domain = sni_extractor.extract(flow)

        # 5. Classify app
        app_type = classifier.classify(domain)

        # 6. Apply rule engine
        action = rule_engine.evaluate(app_type)

        # 7. Update flow stats
        stats.add_flow(app_type)

        # 8. Log decision
        print(f"{domain} -> {app_type.value} -> {action.value}")

    # -----------------------------
    # FINAL REPORT
    # -----------------------------
    print("\n" + stats.generate_report())


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m src.main <pcap_file>")
        exit(1)

    main(sys.argv[1])