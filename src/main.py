import sys
from scapy.all import sniff, raw

# 1. Component Pipeline Imports
from src.core.packet_parser import PacketParser
from src.core.flow_tracker import FlowTracker
from src.core.sni_extractor import SNIExtractor
from src.core.classifier import Classifier
from src.core.rule_engine import RuleEngine
from src.core.statistics import Statistics

# Model & Layout Imports
from src.models.packet import RawPacket
from src.models.enums import Action, AppType
from src.models.rule import Rule


# 2. Define Network Firewall Rules
def build_rules():
    """
    Sets up access control policy actions for parsed signatures.
    """
    return [
        Rule(app_type=AppType.YOUTUBE, action=Action.FORWARD, enabled=True),
        Rule(app_type=AppType.FACEBOOK, action=Action.DROP, enabled=True),
        Rule(app_type=AppType.GITHUB, action=Action.FORWARD, enabled=True),
    ]


# 3. Instantiate Component Pipeline Globally
parser = PacketParser()
flow_tracker = FlowTracker()
sni_extractor = SNIExtractor()
classifier = Classifier()
stats = Statistics()
rule_engine = RuleEngine(build_rules())


# 4. Define the Live Packet Thread Callback
def process_live_packet(scapy_packet):
    """
    This function triggers automatically for every network frame captured live.
    """
    try:
        # Optimization: Only pass frames down the pipe if they have an IPv4 header
        if not scapy_packet.haslayer('IP'):
            return

        # [DEBUG] Dot means the network card saw an IP packet raw
        print(".", end="", flush=True)

        # Convert Scapy object to clean, standard raw binary bytes string
        raw_bytes = raw(scapy_packet)
        timestamp = float(getattr(scapy_packet, 'time', 0))
        
        # Package directly into your structural RawPacket data model
        live_raw_packet = RawPacket(
            timestamp=timestamp, 
            data=raw_bytes, 
            length=len(raw_bytes)
        )

        # Step 1: Parse frame headers via dpkt
        packet = parser.parse(live_raw_packet)
        if not packet:
            return

        # [DEBUG] Plus means the packet passed DPKT header validation checks
        print("+", end="", flush=True)

        # Step 2: Track total metrics
        stats.add_packet(packet.packet_size)

        # Step 3: Track connection flow states (5-tuple tracker)
        flow = flow_tracker.add_packet(packet)
        if not flow:
            return

        # Step 4: Deep Packet Inspection
        # 🌟 FIXED: Passing 'packet.payload' (bytes) to match SNIExtractor API
        domain = sni_extractor.extract(packet.payload)

        # Step 5: Classify application footprint mapping
        app_type = classifier.classify(domain)

        # Step 6: Query Policy Engine for actions
        action = rule_engine.evaluate(app_type)

        # Step 7: Increment engine data structures
        stats.add_flow(app_type)

        # Step 8: Log streaming engine decisions dynamically to standard output
        if domain:
            print(f"\n[LIVE DETECTED] {domain} -> {app_type.value} -> {action.value}")

    except Exception as e:
        # Prints pipeline crashes if data mapping mismatches occur later in the pipe
        print(f"\n[PIPELINE CRASH]: {e}")


# 5. Main Execution Thread Entry-Point
def main():
    print("\n" + "="*50)
    print("         🚀 LIVE DPI ENGINE ACTIVE 🚀          ")
    print("="*50)
    print("[*] Successfully bound socket layer to: wlp0s20f3")
    print("[*] Sniffing live traffic. Browse the web now!")
    print("[*] Legend: '.' = Raw Packet | '+' = Parsed Header")
    print("[*] Press Ctrl+C anytime to halt and print the DPI report.\n")
    
    try:
        # Hook directly into your active hardware interface driver
        sniff(iface='wlp0s20f3', prn=process_live_packet, store=0)
    except KeyboardInterrupt:
        print("\n\n[*] Halting Live Engine Safely...")
        print(stats.generate_report())


if __name__ == "__main__":
    main()