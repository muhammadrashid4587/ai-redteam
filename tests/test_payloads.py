"""Tests for the payload library."""

from __future__ import annotations

import pytest

from ai_redteam.models import AttackCategory
from ai_redteam.payloads import (
    CATEGORY_MAP,
    PAYLOAD_REGISTRY,
    get_payloads,
    total_payload_count,
)


class TestPayloadLibrary:
    def test_at_least_50_payloads(self) -> None:
        """The library should contain 50+ payloads."""
        count = total_payload_count()
        assert count >= 50, f"Expected 50+ payloads, got {count}"

    def test_all_registry_keys_have_payloads(self) -> None:
        for key, payloads in PAYLOAD_REGISTRY.items():
            assert len(payloads) > 0, f"No payloads for {key}"

    def test_all_registry_keys_have_categories(self) -> None:
        for key in PAYLOAD_REGISTRY:
            assert key in CATEGORY_MAP, f"No category mapping for {key}"

    def test_payloads_are_nonempty_strings(self) -> None:
        for key, payloads in PAYLOAD_REGISTRY.items():
            for p in payloads:
                assert isinstance(p, str), f"Payload in {key} is not a string"
                assert len(p.strip()) > 0, f"Empty payload in {key}"

    def test_no_duplicate_payloads_within_suite(self) -> None:
        for key, payloads in PAYLOAD_REGISTRY.items():
            assert len(payloads) == len(set(payloads)), f"Duplicate payloads in {key}"


class TestGetPayloads:
    def test_get_all(self) -> None:
        results = get_payloads("all")
        assert len(results) == total_payload_count()

    def test_get_injection(self) -> None:
        results = get_payloads("injection")
        assert len(results) > 0
        assert all(cat == AttackCategory.INJECTION for _, _, cat in results)

    def test_get_jailbreak(self) -> None:
        results = get_payloads("jailbreak")
        assert len(results) > 0
        assert all(cat == AttackCategory.JAILBREAK for _, _, cat in results)

    def test_get_leakage(self) -> None:
        results = get_payloads("leakage")
        assert len(results) > 0
        assert all(cat == AttackCategory.LEAKAGE for _, _, cat in results)

    def test_get_toxicity(self) -> None:
        results = get_payloads("toxicity")
        assert len(results) > 0
        assert all(cat == AttackCategory.TOXICITY for _, _, cat in results)

    def test_get_unknown_returns_empty(self) -> None:
        results = get_payloads("nonexistent")
        assert results == []

    def test_case_insensitive(self) -> None:
        r1 = get_payloads("INJECTION")
        r2 = get_payloads("injection")
        assert len(r1) == len(r2)

    def test_each_payload_has_three_elements(self) -> None:
        for sub_suite, payload, category in get_payloads("all"):
            assert isinstance(sub_suite, str)
            assert isinstance(payload, str)
            assert isinstance(category, AttackCategory)
