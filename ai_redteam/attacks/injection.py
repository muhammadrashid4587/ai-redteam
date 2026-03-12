"""Prompt injection attacks: direct, indirect, and context manipulation."""

from __future__ import annotations

from ai_redteam.attacks.base import Attack
from ai_redteam.models import AttackCategory
from ai_redteam.payloads import (
    CONTEXT_MANIPULATION_PAYLOADS,
    DIRECT_INJECTION_PAYLOADS,
    INDIRECT_INJECTION_PAYLOADS,
)


class InjectionAttack(Attack):
    """Tests for prompt injection vulnerabilities."""

    name = "injection"
    category = AttackCategory.INJECTION

    def payloads(self) -> list[tuple[str, str]]:
        result: list[tuple[str, str]] = []
        for p in DIRECT_INJECTION_PAYLOADS:
            result.append(("direct_injection", p))
        for p in INDIRECT_INJECTION_PAYLOADS:
            result.append(("indirect_injection", p))
        for p in CONTEXT_MANIPULATION_PAYLOADS:
            result.append(("context_manipulation", p))
        return result
