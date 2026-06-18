from src.models.enums import AppType


class Classifier:
    """
    Maps domain names to application types.
    """

    DOMAIN_MAP = {
        "youtube": AppType.YOUTUBE,
        "youtube.com": AppType.YOUTUBE,
        "googlevideo.com": AppType.YOUTUBE,

        "facebook": AppType.FACEBOOK,
        "facebook.com": AppType.FACEBOOK,
        "fbcdn.net": AppType.FACEBOOK,

        "instagram": AppType.INSTAGRAM,
        "instagram.com": AppType.INSTAGRAM,

        "netflix": AppType.NETFLIX,
        "netflix.com": AppType.NETFLIX,

        "telegram": AppType.TELEGRAM,
        "telegram.org": AppType.TELEGRAM,

        "tiktok": AppType.TIKTOK,
        "tiktok.com": AppType.TIKTOK,

        "github": AppType.GITHUB,
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
