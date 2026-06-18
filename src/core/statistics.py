from collections import defaultdict

from src.models.enums import Action, AppType


class Statistics:
    """
    Collects DPI engine statistics.
    """

    def __init__(self):
        self.raw_packets = 0
        self.total_packets = 0
        self.total_flows = 0
        self.total_bytes = 0
        self.forwarded_packets = 0
        self.dropped_packets = 0

        self.app_counts = defaultdict(int)
        self.dropped_app_counts = defaultdict(int)
        self.dropped_domains = defaultdict(int)

    def add_raw_packet(self):
        self.raw_packets += 1

    def add_packet(self, packet_size: int):
        self.total_packets += 1
        self.total_bytes += packet_size

    def add_flow(self, app_type: AppType):
        self.total_flows += 1
        self.app_counts[app_type] += 1

    def add_decision(
        self,
        action: Action,
        app_type: AppType | None = None,
        domain: str | None = None,
    ):
        if action == Action.DROP:
            self.dropped_packets += 1
            if app_type:
                self.dropped_app_counts[app_type] += 1
            if domain:
                self.dropped_domains[domain] += 1
        else:
            self.forwarded_packets += 1

    def generate_report(self) -> str:
        lines = [
            "\n===== DPI REPORT =====",
            f"Raw Packets   : {self.raw_packets}",
            f"Parsed Packets: {self.total_packets}",
            f"Total Flows   : {self.total_flows}",
            f"Total Bytes   : {self.total_bytes}",
            f"Forwarded     : {self.forwarded_packets}",
            f"Dropped       : {self.dropped_packets}",
            "",
            "Application Breakdown:"
        ]

        for app_type, count in self.app_counts.items():
            lines.append(f"{app_type.value}: {count}")

        if self.dropped_app_counts:
            lines.extend(["", "Dropped Applications:"])
            for app_type, count in self.dropped_app_counts.items():
                lines.append(f"{app_type.value}: {count}")

        if self.dropped_domains:
            lines.extend(["", "Dropped Domains:"])
            for domain, count in self.dropped_domains.items():
                lines.append(f"{domain}: {count}")

        lines.append("======================")

        return "\n".join(lines)
