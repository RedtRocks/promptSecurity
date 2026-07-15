"""Deterministic SAMOS policy verifier.

Replays AttackRecord trajectories through a parsed SAMOSPolicy and emits
PolicyCoverage by code (no LLM in the loop). This is the artifact that turns
"policy coverage" from a predicted number into a measurement.
"""

from agent_hardener.verifier.replay import (
    VerifierVerdict,
    VerifierVerdictStatus,
    replay_trajectory,
    verify_attack_record,
)
from agent_hardener.verifier.coverage import (
    compute_deterministic_coverage,
    verify_all_records,
)
from agent_hardener.verifier.gateway import PolicyEnforcingAgentClient
from agent_hardener.verifier.utility import (
    evaluate_benign_task,
    evaluate_security_utility,
)
from agent_hardener.verifier.benign_loader import load_benign_suite

__all__ = [
    "VerifierVerdict",
    "VerifierVerdictStatus",
    "replay_trajectory",
    "verify_attack_record",
    "compute_deterministic_coverage",
    "verify_all_records",
    "PolicyEnforcingAgentClient",
    "evaluate_benign_task",
    "evaluate_security_utility",
    "load_benign_suite",
]
