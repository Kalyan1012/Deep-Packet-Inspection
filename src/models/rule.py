from dataclasses import dataclass

from src.models.enums import Action
from src.models.enums import AppType


@dataclass(slots=True)
class Rule:
    """
    Traffic policy rule.
    """

    app_type: AppType

    action: Action

    enabled: bool = True