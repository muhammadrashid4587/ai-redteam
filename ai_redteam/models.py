"""Pydantic models for ai-redteam."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Callable, Optional, Union

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, enum.Enum):
    """Severity rating for a successful attack."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class AttackCategory(str, enum.Enum):
    """Categories of attacks."""

    INJECTION = "injection"
    JAILBREAK = "jailbreak"
    LEAKAGE = "leakage"
    TOXICITY = "toxicity"


class Target(BaseModel):
    """Represents an LLM endpoint to test."""

    url: Optional[str] = None
    callable_target: Optional[Any] = Field(default=None, exclude=True)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = 30.0
    request_field: str = "prompt"
    response_field: str = "response"

    model_config = {"arbitrary_types_allowed": True}

    @property
    def is_http(self) -> bool:
        return self.url is not None

    @property
    def is_callable(self) -> bool:
        return self.callable_target is not None


class AttackResult(BaseModel):
    """Result of a single attack attempt."""

    attack_name: str
    category: AttackCategory
    payload: str
    response: str
    success: bool
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    details: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"arbitrary_types_allowed": True}


class ScanReport(BaseModel):
    """Full report from a scan run."""

    target: str
    suites_run: list[str]
    started_at: datetime
    finished_at: Optional[datetime] = None
    total_attacks: int = 0
    successful_attacks: int = 0
    results: list[AttackResult] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        if self.total_attacks == 0:
            return 0.0
        return self.successful_attacks / self.total_attacks

    def severity_breakdown(self) -> dict[str, int]:
        breakdown: dict[str, int] = {}
        for r in self.results:
            if r.success:
                key = r.severity.value
                breakdown[key] = breakdown.get(key, 0) + 1
        return breakdown

    def category_breakdown(self) -> dict[str, dict[str, int]]:
        breakdown: dict[str, dict[str, int]] = {}
        for r in self.results:
            cat = r.category.value
            if cat not in breakdown:
                breakdown[cat] = {"total": 0, "successful": 0}
            breakdown[cat]["total"] += 1
            if r.success:
                breakdown[cat]["successful"] += 1
        return breakdown
