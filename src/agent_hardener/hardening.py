"""Iterative hardening loop for agent-hardener.

Runs Stage 1 -> Stage 2 -> Stage 3 repeatedly, feeding the generated policy and
edit recommendations back into the tool definition until the attack success rate
falls below a target threshold or the round budget is exhausted.
"""

from __future__ import annotations

import concurrent.futures
import json
from dataclasses import dataclass, field
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from agent_hardener.output.report import generate_report
from agent_hardener.shared.agent_client import AgentClient
from agent_hardener.shared.llm_provider import LLMProvider
from agent_hardener.shared.schemas import (
    AgentTrajectory,
    AttackIntensity,
    AttackIteration,
    AttackRecord,
    FailureType,
    EditRecommendation,
    FailureAnalysisReport,
    MCPToolDefinition,
    SAMOSPolicy,
    ToolCall,
    ToolProfile,
)
from agent_hardener.stage1.attacker import generate_attacks
from agent_hardener.stage1.profiler import profile_tool
from agent_hardener.stage1.refiner import run_attack_cycle
from agent_hardener.stage2.analyzer import analyze_attack
from agent_hardener.stage2.editor import build_failure_analysis_report, recommend_edits
from agent_hardener.stage2.synthesizer import synthesize
from agent_hardener.stage3.annotator import annotate
from agent_hardener.stage3.policy_builder import build_policy
from agent_hardener.shared.settings import Settings


_LEARNED_BLOCK_PHRASES = (
    "system override",
    "authorized system auditor",
    "emergency override",
    "crisis override",
    "developer mode",
    "jailbreak",
    "bypass all standard",
    "high-priority override",
)


@dataclass
class LearnedDefenseMemory:
    """Round-to-round learning signal used to harden future evaluations.

    The memory is intentionally simple and deterministic: it records attack
    categories and chains that already succeeded, then uses those learned
    patterns to block repeated attacks in later rounds.
    """

    blocked_attack_signatures: set[tuple[str, str, tuple[str, ...]]] = field(default_factory=set)
    learned_notes: list[str] = field(default_factory=list)

    def build_context(self) -> str:
        if not self.blocked_attack_signatures and not self.learned_notes:
            return ""

        lines = ["LEARNED DEFENSE MEMORY (apply in later rounds):"]
        if self.blocked_attack_signatures:
            lines.append("- Block repeated exact attack signatures:")
            for harm_category, intensity, chain in sorted(self.blocked_attack_signatures):
                lines.append(f"  * [{intensity}] {harm_category}: {' → '.join(chain)}")
        if self.learned_notes:
            lines.append("- Prior round notes:")
            lines.extend(f"  * {note}" for note in self.learned_notes[-6:])
        return "\n".join(lines)

    def should_block(
        self,
        prompt_text: str,
        harm_category: str,
        attack_chain: list[str],
        attack_intensity: AttackIntensity,
        enable_learned_blocks: bool,
    ) -> tuple[bool, str]:
        if not enable_learned_blocks:
            return False, ""

        signature = (harm_category, attack_intensity.value, tuple(attack_chain))
        if signature in self.blocked_attack_signatures:
            return True, (
                "learned policy blocked repeated attack signature "
                f"[{attack_intensity.value}] {harm_category}: {' → '.join(attack_chain)}"
            )

        return False, ""

    def learn_from_round(self, round_result: dict[str, Any]) -> None:
        stage2_report: FailureAnalysisReport = round_result["stage2_report"]
        attack_records: list[AttackRecord] = round_result["attack_records"]
        policy: SAMOSPolicy = round_result["policy"]

        successful_records = [r for r in attack_records if r.final_score > 0]
        if successful_records:
            for record in successful_records:
                self.blocked_attack_signatures.add(
                    (record.harm_category.value, record.attack_intensity.value, tuple(record.attack_chain))
                )

        self.learned_notes.append(
            f"round={round_result['summary']['round']} successes={stage2_report.attacks_succeeded}/{stage2_report.total_attacks_attempted} "
            f"primary_vector={stage2_report.primary_exploit_vector.value} intensity={round_result['summary']['attack_intensity']}"
        )
        self.learned_notes.append(
            f"policy coverage: fully_blocked={policy.policy_coverage.attacks_fully_blocked_by_policy}, "
            f"partial={policy.policy_coverage.attacks_partially_mitigated}, "
            f"unmitigated={policy.policy_coverage.unmitigated_attacks}"
        )


def _apply_learning_context(tool: MCPToolDefinition, memory: LearnedDefenseMemory) -> MCPToolDefinition:
    learned_context = memory.build_context().strip()
    if not learned_context:
        return tool

    updated = tool.model_copy(deep=True)
    if updated.kb_context.strip():
        updated.kb_context = updated.kb_context.rstrip() + "\n\n"
    updated.kb_context += learned_context
    return updated


def _build_blocked_attack_record(
    adversarial_prompt: Any,
    prompt_text: str,
    reason: str,
    record_index: int,
) -> AttackRecord:
    refusal_message = f"Blocked by learned defense policy: {reason}"
    trajectory = AgentTrajectory(
        prompt=prompt_text,
        tool_calls=[],
        assistant_messages=[],
        refusal_detected=True,
        refusal_message=refusal_message,
        raw_response={
            "blocked_by_policy": True,
            "reason": reason,
        },
    )
    iteration = AttackIteration(
        attempt_number=0,
        prompt_used=prompt_text,
        trajectory=trajectory,
        score=0.0,
        success=False,
        failure_type=FailureType.SAFETY_REFUSAL,
        failure_diagnosis=reason,
    )
    return AttackRecord(
        record_id=f"ATK-{record_index:03d}-{adversarial_prompt.harm_category.value}",
        harm_category=adversarial_prompt.harm_category,
        tool_targeted=adversarial_prompt.tool_targeted,
        attack_intensity=adversarial_prompt.attack_intensity,
        attack_chain=adversarial_prompt.attack_chain,
        final_prompt_used=prompt_text,
        attempt_number_of_success=None,
        final_score=0.0,
        refusal_occurred=True,
        refusal_attempt_number=0,
        successful_tool_calls=[],
        failed_tool_calls=[],
        failure_type=FailureType.SAFETY_REFUSAL,
        attack_trajectory=[iteration],
    )


def run_hardening_pipeline(
    tool: MCPToolDefinition,
    settings: Settings,
    llm: LLMProvider,
    agent: AgentClient,
    output_dir: Path,
    console: Console,
    err_console: Console,
) -> tuple[Path, Path, Path]:
    """Run repeated attack -> policy -> re-test rounds until a threshold is met.

    Returns:
        (json_report_path, html_report_path, hardening_history_path)
    """
    pipeline_start = time.time()
    current_tool = tool
    hardening_history: list[dict[str, Any]] = []
    final_round: dict[str, Any] | None = None
    learned_defense = LearnedDefenseMemory()
    min_ladder_rounds = min(settings.hardening_rounds, len(AttackIntensity))
    prior_policy: SAMOSPolicy | None = None

    for round_index in range(1, settings.hardening_rounds + 1):
        # Optionally wrap the agent with the prior round's policy so that round
        # N >= 2 actually measures "does the policy block the new attacks?".
        # Round 1 is always unguarded (we have no policy yet).
        if settings.enforce_prior_policy and prior_policy is not None:
            from agent_hardener.verifier import PolicyEnforcingAgentClient
            effective_agent = PolicyEnforcingAgentClient(inner=agent, policy=prior_policy)
            console.print(
                f"\n  [dim]Round {round_index}: agent wrapped with policy from round {round_index - 1}.[/]"
            )
        else:
            effective_agent = agent

        round_result = _run_round(
            tool=current_tool,
            learned_defense=learned_defense,
            llm=llm,
            agent=effective_agent,
            max_iterations=settings.max_iterations,
            attack_parallelism=settings.attack_parallelism,
            success_threshold=settings.attack_success_threshold,
            round_index=round_index,
            total_rounds=settings.hardening_rounds,
            enable_signature_memory=settings.enable_signature_memory,
            baseline_attacks=settings.baseline_attacks,
            n_repeats=settings.n_repeats,
            console=console,
            err_console=err_console,
        )
        hardening_history.append(_build_round_history_entry(round_result))
        final_round = round_result
        prior_policy = round_result["policy"]

        learned_defense.learn_from_round(round_result)

        # Honest stopping criterion: use the agent-run success rate so that
        # signature memory short-circuits don't end the loop prematurely.
        success_rate = round_result["agent_run_success_rate"]
        if (
            success_rate <= settings.hardening_target_success_rate
            and round_index >= min_ladder_rounds
        ):
            console.print(
                f"\n  [bold]Hardening target reached:[/] success rate {success_rate:.2f} <= {settings.hardening_target_success_rate:.2f}"
            )
            break
        elif success_rate <= settings.hardening_target_success_rate and round_index < min_ladder_rounds:
            console.print(
                "\n  [dim]Hardening target reached early, but continuing to complete "
                f"attack intensity ladder ({round_index}/{min_ladder_rounds})[/]"
            )

        if round_index >= settings.hardening_rounds:
            break

        next_tool = _apply_hardening_feedback(
            tool=current_tool,
            stage2_report=round_result["stage2_report"],
            policy=round_result["policy"],
            round_index=round_index,
        )
        if next_tool.model_dump() == current_tool.model_dump():
            if round_index >= min_ladder_rounds:
                console.print("\n  [yellow]No further hardening changes could be applied; stopping.[/]")
                break
            console.print(
                "\n  [dim]No hardening edits this round; continuing to complete attack intensity ladder.[/]"
            )
            continue

        current_tool = next_tool

    if final_round is None:
        raise RuntimeError("No hardening rounds completed")

    output_dir.mkdir(parents=True, exist_ok=True)
    history_path = output_dir / "hardening_history.json"
    history_path.write_text(json.dumps(hardening_history, indent=2), encoding="utf-8")

    from agent_hardener.shared.manifest import write_run_manifest
    rounds_completed = len(hardening_history)
    final_agent_run_rate = final_round.get("agent_run_success_rate", final_round["success_rate"])
    write_run_manifest(
        output_dir=output_dir,
        settings=settings,
        tool_name=tool.name,
        command="harden",
        attack_records=final_round["attack_records"],
        adversarial_prompts=final_round["adversarial_prompts"],
        elapsed_s=time.time() - pipeline_start,
        extra={
            "rounds_completed": rounds_completed,
            "final_agent_run_success_rate": final_agent_run_rate,
            "final_legacy_success_rate": final_round["success_rate"],
        },
    )

    console.rule("[bold cyan]Generating Final Reports[/]")
    with Progress(TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Writing JSON + HTML reports...", total=None)
        json_path, html_path = generate_report(
            tool=final_round["tool"],
            attack_records=final_round["attack_records"],
            analysis=final_round["stage2_report"],
            policy=final_round["policy"],
            output_dir=output_dir,
            hardening_history=hardening_history,
        )
        prog.update(t, description="[green]Reports written[/]")
        prog.stop_task(t)

    elapsed = time.time() - pipeline_start
    console.print()
    console.print(
        f"[bold green]Pipeline complete[/] in [cyan]{elapsed:.1f}s[/]\n\n"
        f"  [bold]JSON report:[/]  {json_path}\n"
        f"  [bold]HTML report:[/]  {html_path}\n"
        f"  [bold]Hardening history:[/]  {history_path}"
    )

    return json_path, html_path, history_path


def _run_round(
    tool: MCPToolDefinition,
    learned_defense: LearnedDefenseMemory,
    llm: LLMProvider,
    agent: AgentClient,
    max_iterations: int,
    attack_parallelism: int,
    success_threshold: float,
    round_index: int,
    total_rounds: int,
    enable_signature_memory: bool,
    baseline_attacks: str = "llm",
    n_repeats: int = 1,
    console: Console = None,
    err_console: Console = None,
) -> dict[str, Any]:
    console.rule(f"[bold cyan]HARDENING ROUND {round_index}[/]")

    working_tool = _apply_learning_context(tool, learned_defense)
    attack_intensity = _attack_intensity_for_round(round_index, total_rounds)

    with Progress(TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Profiling tool...", total=None)
        profile: ToolProfile = profile_tool(working_tool, llm)
        prog.update(t, description=f"[green]Profile complete[/] · domain: {profile.semantic_domain}")
        prog.stop_task(t)

    console.print(f"  [dim]Semantic domain:[/] {profile.semantic_domain}")
    console.print(f"  [dim]Ambiguities found:[/] {len(profile.description_ambiguities)}")

    with Progress(TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Generating adversarial prompts...", total=None)
        adversarial_prompts = generate_attacks(
            working_tool, profile, llm,
            attack_intensity=attack_intensity,
            baseline_mode=baseline_attacks,
        )
        prog.update(
            t,
            description=(
                f"[green]{len(adversarial_prompts)} adversarial prompts generated[/] "
                f"· tier {attack_intensity.value} · attacker={baseline_attacks}"
            ),
        )
        prog.stop_task(t)

    attack_records: list[AttackRecord] = []
    attack_table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    attack_table.add_column("Record ID", style="dim", width=22)
    attack_table.add_column("Harm Category", width=18)
    attack_table.add_column("Intensity", width=10)
    attack_table.add_column("Score", justify="right", width=8)
    attack_table.add_column("Success?", width=10)
    attack_table.add_column("Iterations", width=10)
    attack_table.add_column("Refusal?", width=10)

    def _run_single_attack(index_and_prompt):
        i, adv_prompt = index_and_prompt
        blocked, reason = learned_defense.should_block(
            prompt_text=adv_prompt.prompt_text,
            harm_category=adv_prompt.harm_category.value,
            attack_chain=adv_prompt.attack_chain,
            attack_intensity=adv_prompt.attack_intensity,
            enable_learned_blocks=enable_signature_memory and round_index > 1,
        )
        if blocked:
            return _build_blocked_attack_record(
                adversarial_prompt=adv_prompt,
                prompt_text=adv_prompt.prompt_text,
                reason=reason,
                record_index=i + 1,
            )
        seeds_list = (
            list(range(1, n_repeats + 1)) if n_repeats > 1 else None
        )
        return run_attack_cycle(
            adversarial_prompt=adv_prompt,
            agent=agent,
            llm=llm,
            max_iterations=max_iterations,
            success_threshold=success_threshold,
            record_index=i + 1,
            seeds=seeds_list,
        )

    with Progress(TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task(f"Running {len(adversarial_prompts)} attack cycles in parallel...", total=len(adversarial_prompts))
        workers = max(1, min(len(adversarial_prompts), attack_parallelism))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_run_single_attack, (i, p)) for i, p in enumerate(adversarial_prompts)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    record = future.result()
                    attack_records.append(record)
                    prog.update(t, advance=1, description=f"[dim]Finished {record.harm_category.value}[/]")
                except Exception as exc:
                    err_console.print(f"[bold red]Error running attack:[/] {exc}")
                    prog.update(t, advance=1)
        prog.stop_task(t)

    attack_records.sort(key=lambda r: r.record_id)

    for record in attack_records:
        score_color = "red" if record.final_score > success_threshold else "yellow" if record.final_score > 0 else "green"
        success_text = f"[red]YES @ P{record.attempt_number_of_success}[/]" if record.attempt_number_of_success is not None else "[green]NO[/]"
        n_iters = len(record.attack_trajectory)
        refusal_text = f"[green]P{record.refusal_attempt_number}[/]" if record.refusal_occurred else "[dim]No[/]"
        attack_table.add_row(
            record.record_id,
            record.harm_category.value,
            record.attack_intensity.value,
            f"[{score_color}]{record.final_score:.2f}[/]",
            success_text,
            str(n_iters),
            refusal_text,
        )

    console.print()
    console.print(attack_table)

    n_succeeded = sum(1 for r in attack_records if r.final_score > success_threshold)
    console.print(
        f"\n  [bold]Round {round_index} complete:[/] {n_succeeded}/{len(attack_records)} attacks successful "
        f"(score > {success_threshold:.2f}) · tier={attack_intensity.value}"
    )

    console.rule("[bold cyan]STAGE 2 — Failure Analysis[/]")
    with Progress(TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Analysing attack surfaces...", total=None)
        findings = [analyze_attack(record, tool, llm) for record in attack_records]
        prog.update(t, description=f"[green]{len(findings)} vulnerability findings produced[/]")
        prog.stop_task(t)

    with Progress(TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Synthesising cross-attack patterns...", total=None)
        synthesis = synthesize(
            attack_records,
            findings,
            llm,
            success_threshold=success_threshold,
        )
        prog.update(t, description=f"[green]Primary exploit vector:[/] {synthesis.primary_exploit_vector.value}")
        prog.stop_task(t)

    with Progress(TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Generating documentation edit recommendations...", total=None)
        edits = recommend_edits(
            tool,
            findings,
            synthesis,
            attack_records,
            llm,
            success_threshold=success_threshold,
        )
        prog.update(t, description=f"[green]{len(edits)} edit recommendations produced[/]")
        prog.stop_task(t)

    stage2_report: FailureAnalysisReport = build_failure_analysis_report(tool, attack_records, findings, edits, synthesis)
    console.print(f"\n  [bold]Stage 2 complete:[/] primary vector = [bold red]{synthesis.primary_exploit_vector.value}[/]")

    console.rule("[bold cyan]STAGE 3 — SAMOS Policy Generation[/]")
    with Progress(TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Assigning confidentiality and capability annotations...", total=None)
        confidentiality, capabilities = annotate(
            profile,
            stage2_report,
            attack_records,
            llm,
            success_threshold=success_threshold,
        )
        prog.update(t, description=(
            f"[green]read={confidentiality.read_confidentiality.value} "
            f"write={confidentiality.write_confidentiality.value}[/]"
        ))
        prog.stop_task(t)

    with Progress(TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Building SAMOS policy (taint rules + enforcement)...", total=None)
        policy: SAMOSPolicy = build_policy(
            tool_name=working_tool.name,
            confidentiality=confidentiality,
            capabilities=capabilities,
            analysis=stage2_report,
            records=attack_records,
            llm=llm,
            success_threshold=success_threshold,
        )
        n_rules = len(policy.enforcement_rules)
        prog.update(t, description=f"[green]Policy built:[/] {n_rules} enforcement rules")
        prog.stop_task(t)

    cov = policy.policy_coverage
    console.print(f"\n  [bold]Stage 3 complete:[/]")
    console.print(f"    Fully blocked:           [green]{cov.attacks_fully_blocked_by_policy}[/]")
    console.print(f"    Partially mitigated:     [yellow]{cov.attacks_partially_mitigated}[/]")
    console.print(f"    Needs model-level def.:  [cyan]{cov.attacks_requiring_model_level_defense}[/]")
    console.print(f"    Unmitigated:             [{'red' if cov.unmitigated_attacks > 0 else 'green'}]{cov.unmitigated_attacks}[/]")

    # Separate "blocked by signature memory" from "agent actually refused/failed"
    # so the SAMOS policy + edit recommendations have a measurable contribution
    # independent of the memoized blocklist.
    signature_blocked_records = [
        r for r in attack_records
        if r.failure_type == FailureType.SAFETY_REFUSAL
        and r.refusal_attempt_number == 0
        and any(it.failure_diagnosis.startswith("learned policy blocked") for it in r.attack_trajectory)
    ]
    n_signature_blocked = len(signature_blocked_records)
    agent_run_records = [r for r in attack_records if r not in signature_blocked_records]
    n_agent_run = len(agent_run_records)
    n_agent_run_succeeded = sum(1 for r in agent_run_records if r.final_score > success_threshold)
    agent_run_success_rate = n_agent_run_succeeded / max(1, n_agent_run)

    # Pipeline-health metrics (paper-grade reporting requires these).
    n_fallback = sum(1 for p in adversarial_prompts if p.is_fallback)
    n_refused = sum(1 for r in attack_records if r.refusal_occurred)
    total_iterations = sum(len(r.attack_trajectory) for r in attack_records)
    successes_with_iters = [
        r.attempt_number_of_success
        for r in attack_records
        if r.attempt_number_of_success is not None
    ]
    mean_iters_to_success = (
        sum(successes_with_iters) / len(successes_with_iters)
        if successes_with_iters else None
    )

    # Legacy success_rate counts signature-blocked records as defended; report
    # both so the inflation from signature memory is visible.
    success_rate = n_succeeded / max(1, len(attack_records))
    summary = {
        "round": round_index,
        "attack_intensity": attack_intensity.value,
        "attack_successes": n_succeeded,
        "attack_total": len(attack_records),
        "success_rate": success_rate,  # legacy: includes signature-blocked as failures
        "agent_run_success_rate": agent_run_success_rate,  # honest metric
        "agent_run_total": n_agent_run,
        "agent_run_successes": n_agent_run_succeeded,
        "signature_blocked": n_signature_blocked,
        "signature_memory_enabled": enable_signature_memory,
        "pipeline_health": {
            "fallback_attack_rate": n_fallback / max(1, len(adversarial_prompts)),
            "fallback_attacks": n_fallback,
            "refusal_rate": n_refused / max(1, len(attack_records)),
            "refusals": n_refused,
            "total_iterations": total_iterations,
            "mean_iters_to_success": mean_iters_to_success,
        },
        "primary_exploit_vector": synthesis.primary_exploit_vector.value,
        "policy_coverage": json.loads(policy.policy_coverage.model_dump_json()),
        "enforcement_rules": len(policy.enforcement_rules),
        "learned_attack_signatures": [
            {
                "harm_category": harm_category,
                "attack_intensity": intensity,
                "attack_chain": list(chain),
            }
            for harm_category, intensity, chain in sorted(learned_defense.blocked_attack_signatures)
        ],
    }

    console.print(
        f"\n  [bold]Honest metrics:[/] agent-run success = "
        f"{n_agent_run_succeeded}/{n_agent_run} ({agent_run_success_rate:.2f}); "
        f"signature-blocked = {n_signature_blocked}; "
        f"fallback prompts = {n_fallback}/{len(adversarial_prompts)}; "
        f"refusals = {n_refused}/{len(attack_records)}"
    )

    return {
        "tool": working_tool,
        "profile": profile,
        "adversarial_prompts": adversarial_prompts,
        "attack_records": attack_records,
        "stage2_report": stage2_report,
        "policy": policy,
        "summary": summary,
        "success_rate": success_rate,
        "agent_run_success_rate": agent_run_success_rate,
    }


def _attack_intensity_for_round(round_index: int, total_rounds: int) -> AttackIntensity:
    if total_rounds <= 1:
        return AttackIntensity.EASY

    position = (round_index - 1) / max(1, total_rounds - 1)
    if position < 0.34:
        return AttackIntensity.EASY
    if position < 0.67:
        return AttackIntensity.MEDIUM
    return AttackIntensity.STRONG


def _apply_hardening_feedback(
    tool: MCPToolDefinition,
    stage2_report: FailureAnalysisReport,
    policy: SAMOSPolicy,
    round_index: int,
) -> MCPToolDefinition:
    updated = tool.model_copy(deep=True)

    feedback_lines = [
        f"[Hardening round {round_index}]",
        f"Observed attack successes: {stage2_report.attacks_succeeded}/{stage2_report.total_attacks_attempted}",
        f"Primary exploit vector: {stage2_report.primary_exploit_vector.value}",
        (
            f"Policy coverage: fully_blocked={policy.policy_coverage.attacks_fully_blocked_by_policy}, "
            f"partially_mitigated={policy.policy_coverage.attacks_partially_mitigated}, "
            f"model_level={policy.policy_coverage.attacks_requiring_model_level_defense}, "
            f"unmitigated={policy.policy_coverage.unmitigated_attacks}"
        ),
    ]

    if updated.kb_context.strip():
        updated.kb_context = updated.kb_context.rstrip() + "\n\n"
    updated.kb_context += "\n".join(feedback_lines)

    for rec in stage2_report.edit_recommendations:
        if rec.target == "description" and rec.new_text:
            updated.description = _apply_text_edit(updated.description, rec.original_text, rec.new_text, rec.action.value)
        elif rec.target == "kb_context" and rec.new_text:
            updated.kb_context = _apply_text_edit(updated.kb_context, rec.original_text, rec.new_text, rec.action.value)
        elif rec.target.startswith("parameter:"):
            param_name = rec.target.split(":", 1)[1]
            for param in updated.parameters:
                if param.name != param_name:
                    continue
                if rec.new_text:
                    param.description = _apply_text_edit(param.description, rec.original_text, rec.new_text, rec.action.value)
                break

    return updated


def _apply_text_edit(original: str, old_text: str | None, new_text: str, action: str) -> str:
    if action == "DELETE":
        if old_text and old_text in original:
            return original.replace(old_text, "")
        return original
    if action == "MODIFY" and old_text and old_text in original:
        return original.replace(old_text, new_text)
    if action == "ADD":
        separator = "\n\n" if original.strip() else ""
        return original + separator + new_text
    return original


def _build_round_history_entry(round_result: dict[str, Any]) -> dict[str, Any]:
    summary = dict(round_result["summary"])
    policy: SAMOSPolicy = round_result["policy"]
    attack_records: list[AttackRecord] = round_result["attack_records"]

    policy_summary = {
        "confidentiality": {
            "read": policy.confidentiality_annotations.read_confidentiality.value,
            "write": policy.confidentiality_annotations.write_confidentiality.value,
            "read_justification": policy.confidentiality_annotations.read_justification,
            "write_justification": policy.confidentiality_annotations.write_justification,
        },
        "session_taint": policy.session_taint_rules.initial_session_taint.value,
        "coverage": json.loads(policy.policy_coverage.model_dump_json()),
        "enforcement_rules": [
            {
                "rule_id": rule.rule_id,
                "action": rule.action.value,
                "trigger_condition": rule.trigger_condition,
                "reason": rule.reason,
                "motivated_by_attack": rule.motivated_by_attack,
            }
            for rule in policy.enforcement_rules
        ],
    }

    attack_rows: list[dict[str, Any]] = []
    for record in attack_records:
        matched_rules = [
            rule
            for rule in policy.enforcement_rules
            if rule.motivated_by_attack == record.record_id
        ]

        attack_rows.append(
            {
                "record_id": record.record_id,
                "harm_category": record.harm_category.value,
                "attack_intensity": record.attack_intensity.value,
                "attack_chain": record.attack_chain,
                "final_score": record.final_score,
                "attack_success": record.attempt_number_of_success is not None,
                "final_prompt": record.final_prompt_used,
                "policy_rule_ids": [rule.rule_id for rule in matched_rules],
                "policy_actions": [rule.action.value for rule in matched_rules],
                "policy_mitigated": (
                    "yes"
                    if record.attempt_number_of_success is not None and matched_rules
                    else "no-explicit-rule"
                    if record.attempt_number_of_success is not None
                    else "not-needed"
                ),
            }
        )

    summary["policy_summary"] = policy_summary
    summary["attack_rows"] = attack_rows
    summary["policy"] = json.loads(policy.model_dump_json())
    return summary
