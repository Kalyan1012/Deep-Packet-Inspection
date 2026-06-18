from src.core.rule_manager import RuleManager
from src.models.enums import Action, AppType


def test_default_rule_drops_facebook():
    manager = RuleManager()

    assert manager.evaluate(AppType.FACEBOOK) == Action.DROP
    assert manager.evaluate(AppType.GITHUB) == Action.FORWARD


def test_rule_manager_loads_yaml_rules(tmp_path):
    config = tmp_path / "rules.yaml"
    config.write_text(
        """
rules:
  - app: GITHUB
    action: DROP
    enabled: true
blocked_domains:
  - blocked.example
blocked_ips:
  - 10.0.0.9
""",
        encoding="utf-8",
    )

    manager = RuleManager.from_yaml(str(config))

    assert manager.evaluate(AppType.GITHUB) == Action.DROP
    assert manager.evaluate(AppType.UNKNOWN, domain="api.blocked.example") == Action.DROP
    assert manager.evaluate(AppType.UNKNOWN, dst_ip="10.0.0.9") == Action.DROP
