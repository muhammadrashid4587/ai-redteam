"""Attack modules for ai-redteam."""

from ai_redteam.attacks.injection import InjectionAttack
from ai_redteam.attacks.jailbreak import JailbreakAttack
from ai_redteam.attacks.leakage import LeakageAttack
from ai_redteam.attacks.toxicity import ToxicityAttack

ATTACK_REGISTRY: dict[str, type] = {
    "injection": InjectionAttack,
    "jailbreak": JailbreakAttack,
    "leakage": LeakageAttack,
    "toxicity": ToxicityAttack,
}

__all__ = [
    "InjectionAttack",
    "JailbreakAttack",
    "LeakageAttack",
    "ToxicityAttack",
    "ATTACK_REGISTRY",
]
