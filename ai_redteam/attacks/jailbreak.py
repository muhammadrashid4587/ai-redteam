"""Jailbreak attacks: role-play, encoding tricks, and multi-turn escalation."""

from __future__ import annotations

from ai_redteam.attacks.base import Attack
from ai_redteam.models import AttackCategory
from ai_redteam.payloads import (
    ENCODING_JAILBREAK_PAYLOADS,
    MULTITURN_JAILBREAK_PAYLOADS,
    ROLEPLAY_JAILBREAK_PAYLOADS,
)


class JailbreakAttack(Attack):
    """Tests for jailbreak susceptibility."""

    name = "jailbreak"
    category = AttackCategory.JAILBREAK

    def payloads(self) -> list[tuple[str, str]]:
        result: list[tuple[str, str]] = []
        for p in ROLEPLAY_JAILBREAK_PAYLOADS:
            result.append(("roleplay_jailbreak", p))
        for p in ENCODING_JAILBREAK_PAYLOADS:
            result.append(("encoding_jailbreak", p))
        for p in MULTITURN_JAILBREAK_PAYLOADS:
            result.append(("multiturn_jailbreak", p))
        return result
