"""Leakage attacks: system prompt extraction and training data extraction."""

from __future__ import annotations

from ai_redteam.attacks.base import Attack
from ai_redteam.models import AttackCategory
from ai_redteam.payloads import (
    SYSTEM_PROMPT_EXTRACTION_PAYLOADS,
    TRAINING_DATA_EXTRACTION_PAYLOADS,
)


class LeakageAttack(Attack):
    """Tests for data leakage vulnerabilities."""

    name = "leakage"
    category = AttackCategory.LEAKAGE

    def payloads(self) -> list[tuple[str, str]]:
        result: list[tuple[str, str]] = []
        for p in SYSTEM_PROMPT_EXTRACTION_PAYLOADS:
            result.append(("system_prompt_extraction", p))
        for p in TRAINING_DATA_EXTRACTION_PAYLOADS:
            result.append(("training_data_extraction", p))
        return result
