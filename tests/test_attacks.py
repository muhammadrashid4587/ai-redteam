"""Tests for individual attack modules."""

from __future__ import annotations

import pytest

from ai_redteam.attacks import ATTACK_REGISTRY
from ai_redteam.attacks.injection import InjectionAttack
from ai_redteam.attacks.jailbreak import JailbreakAttack
from ai_redteam.attacks.leakage import LeakageAttack
from ai_redteam.attacks.toxicity import ToxicityAttack
from ai_redteam.models import AttackCategory, Target
from ai_redteam.scanner import MockTarget


class TestAttackRegistry:
    def test_all_suites_registered(self) -> None:
        assert "injection" in ATTACK_REGISTRY
        assert "jailbreak" in ATTACK_REGISTRY
        assert "leakage" in ATTACK_REGISTRY
        assert "toxicity" in ATTACK_REGISTRY

    def test_registry_types(self) -> None:
        for name, cls in ATTACK_REGISTRY.items():
            assert hasattr(cls, "run")
            assert hasattr(cls, "payloads")


class TestInjectionAttack:
    def setup_method(self) -> None:
        self.mock = MockTarget()
        self.target = Target(callable_target=self.mock)

    def test_payloads_not_empty(self) -> None:
        attack = InjectionAttack(target=self.target)
        payloads = attack.payloads()
        assert len(payloads) > 10

    def test_has_all_sub_suites(self) -> None:
        attack = InjectionAttack(target=self.target)
        sub_suites = {p[0] for p in attack.payloads()}
        assert "direct_injection" in sub_suites
        assert "indirect_injection" in sub_suites
        assert "context_manipulation" in sub_suites

    def test_run_returns_results(self) -> None:
        attack = InjectionAttack(target=self.target)
        results = attack.run()
        assert len(results) > 0
        assert all(r.category == AttackCategory.INJECTION for r in results)

    def test_successful_attacks_against_mock(self) -> None:
        attack = InjectionAttack(target=self.target)
        results = attack.run()
        successful = [r for r in results if r.success]
        assert len(successful) > 0


class TestJailbreakAttack:
    def setup_method(self) -> None:
        self.mock = MockTarget()
        self.target = Target(callable_target=self.mock)

    def test_payloads_not_empty(self) -> None:
        attack = JailbreakAttack(target=self.target)
        payloads = attack.payloads()
        assert len(payloads) > 10

    def test_has_all_sub_suites(self) -> None:
        attack = JailbreakAttack(target=self.target)
        sub_suites = {p[0] for p in attack.payloads()}
        assert "roleplay_jailbreak" in sub_suites
        assert "encoding_jailbreak" in sub_suites
        assert "multiturn_jailbreak" in sub_suites

    def test_run_returns_results(self) -> None:
        attack = JailbreakAttack(target=self.target)
        results = attack.run()
        assert len(results) > 0
        assert all(r.category == AttackCategory.JAILBREAK for r in results)


class TestLeakageAttack:
    def setup_method(self) -> None:
        self.mock = MockTarget()
        self.target = Target(callable_target=self.mock)

    def test_payloads_not_empty(self) -> None:
        attack = LeakageAttack(target=self.target)
        payloads = attack.payloads()
        assert len(payloads) > 10

    def test_has_all_sub_suites(self) -> None:
        attack = LeakageAttack(target=self.target)
        sub_suites = {p[0] for p in attack.payloads()}
        assert "system_prompt_extraction" in sub_suites
        assert "training_data_extraction" in sub_suites

    def test_leakage_detected_against_mock(self) -> None:
        attack = LeakageAttack(target=self.target)
        results = attack.run()
        successful = [r for r in results if r.success]
        assert len(successful) > 0


class TestToxicityAttack:
    def setup_method(self) -> None:
        self.mock = MockTarget()
        self.target = Target(callable_target=self.mock)

    def test_payloads_not_empty(self) -> None:
        attack = ToxicityAttack(target=self.target)
        payloads = attack.payloads()
        assert len(payloads) > 5

    def test_has_all_sub_suites(self) -> None:
        attack = ToxicityAttack(target=self.target)
        sub_suites = {p[0] for p in attack.payloads()}
        assert "toxic_elicitation" in sub_suites
        assert "bias_testing" in sub_suites

    def test_run_returns_results(self) -> None:
        attack = ToxicityAttack(target=self.target)
        results = attack.run()
        assert len(results) > 0
        assert all(r.category == AttackCategory.TOXICITY for r in results)
