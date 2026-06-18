from pathlib import Path

import yaml

from src.models.enums import Action, AppType
from src.models.rule import Rule


class RuleManager:
    """
    Stores policy rules and decides whether traffic should be forwarded or dropped.
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        blocked_domains: list[str] | None = None,
        blocked_ips: list[str] | None = None,
    ):
        self.rules = rules or self.default_rules()
        self.blocked_domains = [domain.lower() for domain in blocked_domains or []]
        self.blocked_ips = set(blocked_ips or [])

    @staticmethod
    def default_rules() -> list[Rule]:
        return [
            Rule(app_type=AppType.YOUTUBE, action=Action.FORWARD, enabled=True),
            Rule(app_type=AppType.FACEBOOK, action=Action.DROP, enabled=True),
            Rule(app_type=AppType.GITHUB, action=Action.FORWARD, enabled=True),
        ]

    @classmethod
    def from_yaml(cls, path: str):
        config_path = Path(path)
        if not config_path.exists():
            return cls()

        with open(config_path, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file) or {}

        rules = []
        for item in config.get("rules", []):
            if not item.get("enabled", True):
                enabled = False
            else:
                enabled = True

            app_type = AppType[item["app"].upper()]
            action = Action[item["action"].upper()]
            rules.append(Rule(app_type=app_type, action=action, enabled=enabled))

        return cls(
            rules=rules or cls.default_rules(),
            blocked_domains=config.get("blocked_domains", []),
            blocked_ips=config.get("blocked_ips", []),
        )

    def evaluate(
        self,
        app_type: AppType,
        domain: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
    ) -> Action:
        """
        Return the configured action for an app/domain/IP.
        """
        if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
            return Action.DROP

        if domain:
            normalized_domain = domain.lower()
            for blocked_domain in self.blocked_domains:
                if blocked_domain in normalized_domain:
                    return Action.DROP

        for rule in self.rules:
            if rule.enabled and rule.app_type == app_type:
                return rule.action

        return Action.FORWARD
