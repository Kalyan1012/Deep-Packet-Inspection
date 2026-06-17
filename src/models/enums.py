from enum import Enum


class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    UNKNOWN = "UNKNOWN"


class AppType(Enum):
    UNKNOWN = "UNKNOWN"

    YOUTUBE = "YOUTUBE"
    GOOGLE = "GOOGLE"
    FACEBOOK = "FACEBOOK"
    INSTAGRAM = "INSTAGRAM"
    NETFLIX = "NETFLIX"
    TELEGRAM = "TELEGRAM"
    TIKTOK = "TIKTOK"
    GITHUB = "GITHUB"


class Action(Enum):
    FORWARD = "FORWARD"
    DROP = "DROP"


class FlowState(Enum):
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"