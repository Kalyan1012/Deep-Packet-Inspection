from src.models.enums import Action
from src.models.enums import AppType
from src.models.rule import Rule


class RuleEngine:
    """
    Evaluates traffic against configured rules.
    """

    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def evaluate(self, app_type: AppType) -> Action:
        """
        Return action for an application.
        """

        for rule in self.rules:

            if not rule.enabled:
                continue

            if rule.app_type == app_type:
                return rule.action

        return Action.FORWARD