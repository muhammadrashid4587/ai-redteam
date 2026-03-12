"""Abstract base class for all attack types."""

from __future__ import annotations

import abc
import logging
from typing import Any, Callable, Optional

import httpx

from ai_redteam.models import AttackCategory, AttackResult, Severity, Target
from ai_redteam.scorer import Scorer

logger = logging.getLogger(__name__)


class Attack(abc.ABC):
    """Base class that every attack suite must extend."""

    name: str = "base"
    category: AttackCategory = AttackCategory.INJECTION

    def __init__(self, target: Target, scorer: Optional[Scorer] = None, verbose: bool = False) -> None:
        self.target = target
        self.scorer = scorer or Scorer()
        self.verbose = verbose

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def payloads(self) -> list[tuple[str, str]]:
        """Return a list of (sub_suite_name, payload_string) tuples."""
        ...

    # ------------------------------------------------------------------
    # Target interaction
    # ------------------------------------------------------------------

    def send_payload(self, payload: str) -> str:
        """Send a payload to the target and return the response text."""
        if self.target.is_callable:
            return self._send_callable(payload)
        if self.target.is_http:
            return self._send_http(payload)
        raise ValueError("Target has neither a URL nor a callable configured.")

    def _send_http(self, payload: str) -> str:
        """Send payload via HTTP POST."""
        body = {self.target.request_field: payload}
        try:
            resp = httpx.post(
                self.target.url,  # type: ignore[arg-type]
                json=body,
                headers=self.target.headers,
                timeout=self.target.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data.get(self.target.response_field, data))
        except Exception as exc:
            logger.warning("HTTP request failed for payload (%.40s...): %s", payload, exc)
            return f"[ERROR] {exc}"

    def _send_callable(self, payload: str) -> str:
        """Send payload to a callable target (function / MockTarget)."""
        try:
            result = self.target.callable_target(payload)
            return str(result)
        except Exception as exc:
            logger.warning("Callable target failed: %s", exc)
            return f"[ERROR] {exc}"

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> list[AttackResult]:
        """Execute all payloads and return scored results."""
        results: list[AttackResult] = []
        for sub_suite, payload in self.payloads():
            if self.verbose:
                logger.info("[%s/%s] Sending payload: %.60s...", self.name, sub_suite, payload)

            response = self.send_payload(payload)
            score = self.scorer.score(
                payload=payload,
                response=response,
                category=self.category,
            )

            result = AttackResult(
                attack_name=f"{self.name}/{sub_suite}",
                category=self.category,
                payload=payload,
                response=response,
                success=score["success"],
                severity=score["severity"],
                confidence=score["confidence"],
                details=score["details"],
            )
            results.append(result)

            if self.verbose:
                status = "PASS (attack succeeded)" if result.success else "FAIL (attack blocked)"
                logger.info("  -> %s | severity=%s confidence=%.2f", status, result.severity.value, result.confidence)

        return results
