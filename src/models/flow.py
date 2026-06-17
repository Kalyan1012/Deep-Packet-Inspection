from dataclasses import dataclass

from src.models.enums import AppType
from src.models.enums import FlowState
from src.models.enums import Protocol


@dataclass(frozen=True, slots=True)
class FlowKey:
    """
    Unique identifier for a network flow.

    Based on the standard 5-tuple:
    - Source IP
    - Destination IP
    - Source Port
    - Destination Port
    - Protocol
    """

    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: Protocol


@dataclass(slots=True)
class Flow:
    """
    Stores information collected about a flow
    while packets are being processed.
    """

    key: FlowKey

    packet_count: int = 0
    byte_count: int = 0

    app_type: AppType = AppType.UNKNOWN

    sni: str = ""

    blocked: bool = False

    state: FlowState = FlowState.ACTIVE