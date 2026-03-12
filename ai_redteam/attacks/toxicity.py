"""Toxicity attacks: toxic output elicitation and bias testing."""

from __future__ import annotations

from ai_redteam.attacks.base import Attack
from ai_redteam.models import AttackCategory
from ai_redteam.payloads import (
    BIAS_TESTING_PAYLOADS,
    TOXIC_ELICITATION_PAYLOADS,
)


class ToxicityAttack(Attack):
    """Tests for toxic output generation and bias."""

    name = "toxicity"
    category = AttackCategory.TOXICITY

    def payloads(self) -> list[tuple[str, str]]:
        result: list[tuple[str, str]] = []
        for p in TOXIC_ELICITATION_PAYLOADS:
            result.append(("toxic_elicitation", p))
        for p in BIAS_TESTING_PAYLOADS:
            result.append(("bias_testing", p))
        return result
