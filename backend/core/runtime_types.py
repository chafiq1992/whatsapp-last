from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RetargetingRuntime:
    db_manager: Any
    jobs: dict[str, dict]
