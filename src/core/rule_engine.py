from src.core.rule_manager import RuleManager
from src.models.enums import Action, AppType
from src.models.rule import Rule


class RuleEngine(RuleManager):
    """
    Backward-compatible name for the policy rule manager.
    """

    def __init__(self, rules: list[Rule]):
        super().__init__(rules=rules)

    def evaluate(self, app_type: AppType) -> Action:
        """
        Return action for an application.
        """
        return super().evaluate(app_type=app_type)
