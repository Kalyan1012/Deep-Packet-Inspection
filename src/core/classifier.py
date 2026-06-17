from src.models.enums import AppType


class Classifier:
    """
    Maps domain names to application types.
    """

    DOMAIN_MAP = {
        "youtube.com": AppType.YOUTUBE,
        "googlevideo.com": AppType.YOUTUBE,

        "facebook.com": AppType.FACEBOOK,

        "github.com": AppType.GITHUB,
    }

    @classmethod
    def classify(cls, domain: str | None) -> AppType:
        if not domain:
            return AppType.UNKNOWN

        domain = domain.lower()

        for known_domain, app_type in cls.DOMAIN_MAP.items():
            if known_domain in domain:
                return app_type

        return AppType.UNKNOWN