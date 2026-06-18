from collections import defaultdict

from src.models.enums import AppType


class Statistics:
    """
    Collects DPI engine statistics.
    """

    def __init__(self):
        self.total_packets = 0
        self.total_flows = 0
        self.total_bytes = 0

        self.app_counts = defaultdict(int)

    def add_packet(self, packet_size: int):
        self.total_packets += 1
        self.total_bytes += packet_size

    def add_flow(self, app_type: AppType):
        self.total_flows += 1
        self.app_counts[app_type] += 1

    def generate_report(self) -> str:
        lines = [
            "\n===== DPI REPORT =====",
            f"Total Packets : {self.total_packets}",
            f"Total Flows   : {self.total_flows}",
            f"Total Bytes   : {self.total_bytes}",
            "",
            "Application Breakdown:"
        ]

        for app_type, count in self.app_counts.items():
            lines.append(f"{app_type.value}: {count}")

        lines.append("======================")

        return "\n".join(lines)