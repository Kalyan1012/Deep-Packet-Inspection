import argparse

from src.core.dpi_engine import DpiEngine
from src.core.rule_manager import RuleManager


def main():
    arg_parser = argparse.ArgumentParser(description="Run the DPI engine.")
    arg_parser.add_argument("--iface", help="Network interface for live capture")
    arg_parser.add_argument("--pcap", help="Read packets from a PCAP file instead of live capture")
    arg_parser.add_argument(
        "--output",
        default="output/filtered.pcap",
        help="Filtered PCAP output path for --pcap mode"
    )
    arg_parser.add_argument(
        "--rules",
        default="config/rules.yaml",
        help="YAML rule config path"
    )
    args = arg_parser.parse_args()

    print("\n" + "="*50)
    print("          LIVE DPI ENGINE ACTIVE          ")
    print("="*50)
    print("[*] Legend: '.' = Raw Packet | '+' = Parsed Header")

    engine = DpiEngine(rule_manager=RuleManager.from_yaml(args.rules))

    try:
        if args.pcap:
            print(f"[*] Reading packets from: {args.pcap}\n")
            engine.process_pcap(args.pcap, args.output)
            return

        if not args.iface:
            arg_parser.error("live capture requires --iface, or use --pcap for offline analysis")

        print(f"[*] Successfully bound socket layer to: {args.iface}")
        print("[*] Sniffing live traffic. Browse the web now!")
        print("[*] Press Ctrl+C anytime to halt and print the DPI report.\n")

        # Hook directly into your active hardware interface driver
        from scapy.all import sniff

        sniff(iface=args.iface, prn=engine.process_live_scapy_packet, store=0)
    except KeyboardInterrupt:
        print("\n\n[*] Halting Live Engine Safely...")
        print(engine.report())


if __name__ == "__main__":
    main()
