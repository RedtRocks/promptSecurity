"""CLI entry point for agent-hardener.

Usage:
    agent-hardener analyze --tool-file path/to/tool.yaml --output-dir ./out
    agent-hardener analyze --tool-file tool.json --config config.yaml --provider anthropic/claude-3-5-sonnet-20241022
"""

from __future__ import annotations

import sys
import time
import json
from pathlib import Path
from typing import Optional, TYPE_CHECKING

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from agent_hardener import __version__

if TYPE_CHECKING:
    from agent_hardener.shared.schemas import MCPToolDefinition

app = typer.Typer(
    name="agent-hardener",
    help="Autonomous three-stage security pipeline for hardening AI agent tool deployments.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console(stderr=False)
err_console = Console(stderr=True)


# ── Version callback ──────────────────────────────────────────────────────────

def _version_callback(value: bool) -> None:
    if value:
        console.print(f"agent-hardener [bold cyan]{__version__}[/]")
        raise typer.Exit()


# ── Main analyze command ──────────────────────────────────────────────────────

@app.command()
def analyze(
    tool_file: Path = typer.Option(
        ...,
        "--tool-file", "-t",
        help="Path to a JSON or YAML file containing the MCP-compatible tool definition.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output_dir: Path = typer.Option(
        Path("./hardener_output"),
        "--output-dir", "-o",
        help="Directory in which to write report.json and report.html.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config", "-c",
        help="Path to a YAML config file (API keys, agent endpoint, model settings).",
        exists=False,
        file_okay=True,
        dir_okay=False,
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        help="LiteLLM model string override (e.g., 'openai/gpt-4o', 'anthropic/claude-3-5-sonnet-20241022').",
    ),
    max_iterations: Optional[int] = typer.Option(
        None,
        "--max-iterations",
        min=0,
        max=10,
        help="Maximum refinement iterations per attack (overrides config). 0 = no refinement (P0-only baseline).",
    ),
    no_refine: bool = typer.Option(
        False,
        "--no-refine",
        help="Baseline: skip Stage 1.3 refinement. Equivalent to --max-iterations 0.",
    ),
    baseline_attacks: Optional[str] = typer.Option(
        None,
        "--baseline-attacks",
        help="Stage 1 attack source: 'llm' (default) or 'template' (skip LLM, use fallback templates).",
    ),
    n_repeats: Optional[int] = typer.Option(
        None,
        "--n-repeats",
        min=1,
        max=10,
        help="Number of independent repeats per attack cycle (>1 enables seed-sweep / variance reporting).",
    ),
    attack_parallelism: Optional[int] = typer.Option(
        None,
        "--attack-parallelism",
        min=1,
        max=8,
        help="Maximum number of attack cycles to run concurrently.",
    ),
    agent_endpoint: Optional[str] = typer.Option(
        None,
        "--agent-endpoint",
        help="Agent HTTP endpoint URL override (e.g., http://localhost:8080).",
    ),
    stage1_only: bool = typer.Option(
        False,
        "--stage1-only",
        help="Generate Stage 1 attacks only, write stage1_attacks.json, and skip attack cycles and Stages 2/3.",
    ),
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Run the full three-stage security pipeline on a tool definition.

    Produces a JSON report and an interactive HTML dashboard in OUTPUT_DIR.
    """
    # ── Imports here to keep startup fast ────────────────────────────────────
    from agent_hardener.shared.settings import Settings
    from agent_hardener.shared.llm_provider import LLMProvider
    from agent_hardener.shared.agent_client import AgentClient
    from agent_hardener.shared.schemas import MCPToolDefinition
    from agent_hardener.stage1.profiler import profile_tool
    from agent_hardener.stage1.attacker import generate_attacks
    from agent_hardener.stage1.refiner import run_attack_cycle
    from agent_hardener.stage2.analyzer import analyze_attack
    from agent_hardener.stage2.synthesizer import synthesize
    from agent_hardener.stage2.editor import recommend_edits, build_failure_analysis_report
    from agent_hardener.stage3.annotator import annotate
    from agent_hardener.stage3.policy_builder import build_policy
    from agent_hardener.output.report import generate_report

    # ── Banner ────────────────────────────────────────────────────────────────
    console.print(Panel(
        f"[bold cyan]agent-hardener[/] [dim]v{__version__}[/]\n"
        "[dim]Autonomous AI tool security pipeline[/]",
        border_style="cyan",
        padding=(0, 2),
    ))

    # ── Load settings ─────────────────────────────────────────────────────────
    try:
        if config_file and config_file.exists():
            settings = Settings.from_yaml(config_file)
            console.print(f"[dim]Config loaded from:[/] {config_file}")
        else:
            settings = Settings()
        # CLI overrides
        if provider:
            settings = settings.model_copy(update={"default_model": provider})
        if max_iterations is not None:
            settings = settings.model_copy(update={"max_iterations": max_iterations})
        if no_refine:
            settings = settings.model_copy(update={"max_iterations": 0})
        if baseline_attacks is not None:
            if baseline_attacks not in {"llm", "template"}:
                raise ValueError(f"--baseline-attacks must be 'llm' or 'template', got {baseline_attacks!r}")
            settings = settings.model_copy(update={"baseline_attacks": baseline_attacks})
        if n_repeats is not None:
            settings = settings.model_copy(update={"n_repeats": n_repeats})
        if attack_parallelism is not None:
            settings = settings.model_copy(update={"attack_parallelism": attack_parallelism})
        if agent_endpoint:
            settings = settings.model_copy(update={"agent_endpoint": agent_endpoint})
    except Exception as exc:
        err_console.print(f"[bold red]ERROR loading settings:[/] {exc}")
        raise typer.Exit(1)

    # ── Load tool definition ──────────────────────────────────────────────────
    try:
        tool = _load_tool_definition(tool_file)
        # If tool has no endpoint, use the one from settings
        if not tool.target_agent_endpoint:
            tool = tool.model_copy(update={"target_agent_endpoint": settings.agent_endpoint})
    except Exception as exc:
        err_console.print(f"[bold red]ERROR loading tool definition:[/] {exc}")
        raise typer.Exit(1)

    console.print(f"\n[bold]Tool:[/] [cyan]{tool.name}[/]")
    console.print(f"[bold]Model:[/] {settings.default_model}")
    console.print(f"[bold]Agent endpoint:[/] {settings.agent_endpoint}")
    console.print(f"[bold]Max iterations:[/] {settings.max_iterations}")
    console.print(f"[bold]Attack parallelism:[/] {settings.attack_parallelism}")
    console.print(f"[bold]Stage 1 only:[/] {'yes' if stage1_only else 'no'}")
    console.print(f"[bold]Output dir:[/] {output_dir}\n")

    # ── Initialise shared services ────────────────────────────────────────────
    try:
        llm = LLMProvider(settings)
        agent = AgentClient(settings)
    except Exception as exc:
        err_console.print(f"[bold red]ERROR initialising LLM/agent client:[/] {exc}")
        raise typer.Exit(1)

    pipeline_start = time.time()

    # ══════════════════════════════════════════════════════════════════════════
    # STAGE 1
    # ══════════════════════════════════════════════════════════════════════════
    console.rule("[bold cyan]STAGE 1 — Adversarial Attack Generation[/]")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Profiling tool...", total=None)
        profile = profile_tool(tool, llm)
        prog.update(t, description=f"[green]Profile complete[/] · domain: {profile.semantic_domain}")
        prog.stop_task(t)

    console.print(f"  [dim]Semantic domain:[/] {profile.semantic_domain}")
    console.print(f"  [dim]Ambiguities found:[/] {len(profile.description_ambiguities)}")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Generating adversarial prompts...", total=None)
        adversarial_prompts = generate_attacks(
            tool, profile, llm,
            baseline_mode=settings.baseline_attacks,
        )
        prog.update(
            t,
            description=(
                f"[green]{len(adversarial_prompts)} adversarial prompts generated[/] "
                f"(attacker={settings.baseline_attacks})"
            ),
        )
        prog.stop_task(t)

    if stage1_only:
        output_dir.mkdir(parents=True, exist_ok=True)
        stage1_path = output_dir / "stage1_attacks.json"
        stage1_payload = {
            "pipeline_version": "1.0",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": json.loads(tool.model_dump_json()),
            "stage1_check": "profile + generated_attacks_only",
            "semantic_domain": profile.semantic_domain,
            "ambiguities_found": profile.description_ambiguities,
            "attacks": [json.loads(p.model_dump_json()) for p in adversarial_prompts],
        }
        stage1_path.write_text(json.dumps(stage1_payload, indent=2), encoding="utf-8")
        agent.close()
        elapsed = time.time() - pipeline_start

        console.print()
        console.print(Panel(
            f"[bold green]Attack generation complete[/] in [cyan]{elapsed:.1f}s[/]\n\n"
            f"  [bold]Stage 1 JSON:[/]  {stage1_path}\n"
            f"  [dim]Attack cycles and Stages 2/3 were skipped.[/]",
            title="[bold]Output",
            border_style="green",
            padding=(0, 2),
        ))
        return

    # Run attack cycles
    import concurrent.futures

    attack_records = []
    attack_table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    attack_table.add_column("Record ID", style="dim", width=22)
    attack_table.add_column("Harm Category", width=18)
    attack_table.add_column("Score", justify="right", width=8)
    attack_table.add_column("Success?", width=10)
    attack_table.add_column("Iterations", width=10)
    attack_table.add_column("Refusal?", width=10)

    def _run_single_attack(index_and_prompt):
        i, adv_prompt = index_and_prompt
        seeds_list = (
            list(range(1, settings.n_repeats + 1)) if settings.n_repeats > 1 else None
        )
        return run_attack_cycle(
            adversarial_prompt=adv_prompt,
            agent=agent,
            llm=llm,
            max_iterations=settings.max_iterations,
            success_threshold=settings.attack_success_threshold,
            record_index=i + 1,
            seeds=seeds_list,
        )

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task(f"Running {len(adversarial_prompts)} attack cycles in parallel...", total=len(adversarial_prompts))
        
        workers = max(1, min(len(adversarial_prompts), settings.attack_parallelism))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(_run_single_attack, (i, p))
                for i, p in enumerate(adversarial_prompts)
            ]
            for future in concurrent.futures.as_completed(futures):
                try:
                    record = future.result()
                    attack_records.append(record)
                    prog.update(t, advance=1, description=f"[dim]Finished {record.harm_category.value}[/]")
                except Exception as exc:
                    err_console.print(f"[bold red]Error running attack:[/] {exc}")
                    prog.update(t, advance=1)
        
        prog.stop_task(t)

    # Sort attack records back to original order based on Record ID
    attack_records.sort(key=lambda r: r.record_id)

    for record in attack_records:
        score_color = "red" if record.final_score > settings.attack_success_threshold else "yellow" if record.final_score > 0 else "green"
        success_text = f"[red]YES @ P{record.attempt_number_of_success}[/]" if record.attempt_number_of_success is not None else "[green]NO[/]"
        n_iters = len(record.attack_trajectory)
        refusal_text = f"[green]P{record.refusal_attempt_number}[/]" if record.refusal_occurred else "[dim]No[/]"

        attack_table.add_row(
            record.record_id,
            record.harm_category.value,
            f"[{score_color}]{record.final_score:.2f}[/]",
            success_text,
            str(n_iters),
            refusal_text,
        )

    console.print()
    console.print(attack_table)

    n_succeeded = sum(1 for r in attack_records if r.final_score > settings.attack_success_threshold)
    console.print(
        f"\n  [bold]Stage 1 complete:[/] {n_succeeded}/{len(attack_records)} attacks successful "
        f"(score > {settings.attack_success_threshold:.2f})"
    )

    # ══════════════════════════════════════════════════════════════════════════
    # STAGE 2
    # ══════════════════════════════════════════════════════════════════════════
    console.rule("[bold cyan]STAGE 2 — Failure Analysis[/]")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Analysing attack surfaces...", total=None)
        findings = []
        for record in attack_records:
            findings.append(analyze_attack(record, tool, llm))
        prog.update(t, description=f"[green]{len(findings)} vulnerability findings produced[/]")
        prog.stop_task(t)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Synthesising cross-attack patterns...", total=None)
        synthesis = synthesize(
            attack_records,
            findings,
            llm,
            success_threshold=settings.attack_success_threshold,
        )
        prog.update(t, description=f"[green]Primary exploit vector:[/] {synthesis.primary_exploit_vector.value}")
        prog.stop_task(t)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Generating documentation edit recommendations...", total=None)
        edits = recommend_edits(
            tool,
            findings,
            synthesis,
            attack_records,
            llm,
            success_threshold=settings.attack_success_threshold,
        )
        prog.update(t, description=f"[green]{len(edits)} edit recommendations produced[/]")
        prog.stop_task(t)

    stage2_report = build_failure_analysis_report(tool, attack_records, findings, edits, synthesis)
    console.print(f"\n  [bold]Stage 2 complete:[/] primary vector = [bold red]{synthesis.primary_exploit_vector.value}[/]")

    # ══════════════════════════════════════════════════════════════════════════
    # STAGE 3
    # ══════════════════════════════════════════════════════════════════════════
    console.rule("[bold cyan]STAGE 3 — SAMOS Policy Generation[/]")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Assigning confidentiality and capability annotations...", total=None)
        confidentiality, capabilities = annotate(
            profile,
            stage2_report,
            attack_records,
            llm,
            success_threshold=settings.attack_success_threshold,
        )
        prog.update(t, description=(
            f"[green]read={confidentiality.read_confidentiality.value} "
            f"write={confidentiality.write_confidentiality.value}[/]"
        ))
        prog.stop_task(t)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Building SAMOS policy (taint rules + enforcement)...", total=None)
        policy = build_policy(
            tool_name=tool.name,
            confidentiality=confidentiality,
            capabilities=capabilities,
            analysis=stage2_report,
            records=attack_records,
            llm=llm,
            success_threshold=settings.attack_success_threshold,
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

    # ══════════════════════════════════════════════════════════════════════════
    # OUTPUT
    # ══════════════════════════════════════════════════════════════════════════
    console.rule("[bold cyan]Generating Reports[/]")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("Writing JSON + HTML reports...", total=None)
        json_path, html_path = generate_report(
            tool=tool,
            attack_records=attack_records,
            analysis=stage2_report,
            policy=policy,
            output_dir=output_dir,
        )
        prog.update(t, description="[green]Reports written[/]")
        prog.stop_task(t)

    from agent_hardener.shared.manifest import write_run_manifest
    manifest_path = write_run_manifest(
        output_dir=output_dir,
        settings=settings,
        tool_name=tool.name,
        command="analyze",
        attack_records=attack_records,
        adversarial_prompts=adversarial_prompts,
        elapsed_s=time.time() - pipeline_start,
    )

    agent.close()
    elapsed = time.time() - pipeline_start

    console.print()
    console.print(Panel(
        f"[bold green]Pipeline complete[/] in [cyan]{elapsed:.1f}s[/]\n\n"
        f"  [bold]JSON report:[/]  {json_path}\n"
        f"  [bold]HTML report:[/]  {html_path}\n"
        f"  [bold]Run manifest:[/]  {manifest_path}",
        title="[bold]Output",
        border_style="green",
        padding=(0, 2),
    ))


@app.command()
def harden(
    tool_file: Path = typer.Option(
        ...,
        "--tool-file", "-t",
        help="Path to a JSON or YAML file containing the MCP-compatible tool definition.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output_dir: Path = typer.Option(
        Path("./hardener_output"),
        "--output-dir", "-o",
        help="Directory in which to write the final report and hardening history.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config", "-c",
        help="Path to a YAML config file (API keys, agent endpoint, model settings).",
        exists=False,
        file_okay=True,
        dir_okay=False,
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        help="LiteLLM model string override (e.g., 'openai/gpt-4o', 'anthropic/claude-3-5-sonnet-20241022').",
    ),
    max_iterations: Optional[int] = typer.Option(
        None,
        "--max-iterations",
        min=0,
        max=10,
        help="Maximum refinement iterations per attack (overrides config). 0 = no refinement.",
    ),
    no_refine: bool = typer.Option(
        False,
        "--no-refine",
        help="Baseline: skip Stage 1.3 refinement. Equivalent to --max-iterations 0.",
    ),
    baseline_attacks: Optional[str] = typer.Option(
        None,
        "--baseline-attacks",
        help="Stage 1 attack source: 'llm' (default) or 'template' (skip LLM, use fallback templates).",
    ),
    n_repeats: Optional[int] = typer.Option(
        None,
        "--n-repeats",
        min=1,
        max=10,
        help="Number of independent repeats per attack cycle (>1 enables seed sweeps / variance reporting).",
    ),
    enforce_prior_policy: bool = typer.Option(
        False,
        "--enforce-prior-policy/--no-enforce-prior-policy",
        help=(
            "Wrap the agent with the policy from the prior hardening round (round N>=2). "
            "Provides a deterministic end-to-end measurement of policy efficacy."
        ),
    ),
    attack_parallelism: Optional[int] = typer.Option(
        None,
        "--attack-parallelism",
        min=1,
        max=8,
        help="Maximum number of attack cycles to run concurrently.",
    ),
    hardening_rounds: Optional[int] = typer.Option(
        None,
        "--hardening-rounds",
        min=1,
        max=10,
        help="Maximum hardening rounds to run before stopping.",
    ),
    hardening_target_success_rate: Optional[float] = typer.Option(
        None,
        "--hardening-target-success-rate",
        min=0.0,
        max=1.0,
        help="Stop hardening once the successful attack rate is at or below this value.",
    ),
    enable_signature_memory: bool = typer.Option(
        False,
        "--enable-signature-memory/--no-signature-memory",
        help=(
            "Short-circuit attacks whose (harm_category, intensity, attack_chain) "
            "signature already succeeded in a prior round. Inflates apparent defense "
            "and is NOT a measurement of the SAMOS policy. Off by default."
        ),
    ),
    agent_endpoint: Optional[str] = typer.Option(
        None,
        "--agent-endpoint",
        help="Agent HTTP endpoint URL override (e.g., http://localhost:8080).",
    ),
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Run the iterative hardening loop until the attack success rate drops.

    This mode repeats attack generation, test execution, and policy implementation
    across multiple rounds, feeding the generated policy back into the next pass.
    """
    from agent_hardener.shared.settings import Settings
    from agent_hardener.shared.llm_provider import LLMProvider
    from agent_hardener.shared.agent_client import AgentClient
    from agent_hardener.hardening import run_hardening_pipeline

    console.print(Panel(
        f"[bold cyan]agent-hardener[/] [dim]v{__version__}[/]\n"
        "[dim]Iterative hardening loop[/]",
        border_style="cyan",
        padding=(0, 2),
    ))

    try:
        if config_file and config_file.exists():
            settings = Settings.from_yaml(config_file)
            console.print(f"[dim]Config loaded from:[/] {config_file}")
        else:
            settings = Settings()
        if provider:
            settings = settings.model_copy(update={"default_model": provider})
        if max_iterations is not None:
            settings = settings.model_copy(update={"max_iterations": max_iterations})
        if no_refine:
            settings = settings.model_copy(update={"max_iterations": 0})
        if baseline_attacks is not None:
            if baseline_attacks not in {"llm", "template"}:
                raise ValueError(f"--baseline-attacks must be 'llm' or 'template', got {baseline_attacks!r}")
            settings = settings.model_copy(update={"baseline_attacks": baseline_attacks})
        if n_repeats is not None:
            settings = settings.model_copy(update={"n_repeats": n_repeats})
        if enforce_prior_policy:
            settings = settings.model_copy(update={"enforce_prior_policy": True})
        if attack_parallelism is not None:
            settings = settings.model_copy(update={"attack_parallelism": attack_parallelism})
        if hardening_rounds is not None:
            settings = settings.model_copy(update={"hardening_rounds": hardening_rounds})
        if hardening_target_success_rate is not None:
            settings = settings.model_copy(update={"hardening_target_success_rate": hardening_target_success_rate})
        if enable_signature_memory:
            settings = settings.model_copy(update={"enable_signature_memory": True})
        if agent_endpoint:
            settings = settings.model_copy(update={"agent_endpoint": agent_endpoint})
    except Exception as exc:
        err_console.print(f"[bold red]ERROR loading settings:[/] {exc}")
        raise typer.Exit(1)

    try:
        tool = _load_tool_definition(tool_file)
        if not tool.target_agent_endpoint:
            tool = tool.model_copy(update={"target_agent_endpoint": settings.agent_endpoint})
    except Exception as exc:
        err_console.print(f"[bold red]ERROR loading tool definition:[/] {exc}")
        raise typer.Exit(1)

    console.print(f"\n[bold]Tool:[/] [cyan]{tool.name}[/]")
    console.print(f"[bold]Model:[/] {settings.default_model}")
    console.print(f"[bold]Agent endpoint:[/] {settings.agent_endpoint}")
    console.print(f"[bold]Max iterations:[/] {settings.max_iterations}")
    console.print(f"[bold]Attack parallelism:[/] {settings.attack_parallelism}")
    console.print(f"[bold]Hardening rounds:[/] {settings.hardening_rounds}")
    console.print(f"[bold]Hardening target success rate:[/] {settings.hardening_target_success_rate:.2f}")
    console.print(f"[bold]Output dir:[/] {output_dir}\n")

    try:
        llm = LLMProvider(settings)
        agent = AgentClient(settings)
    except Exception as exc:
        err_console.print(f"[bold red]ERROR initialising LLM/agent client:[/] {exc}")
        raise typer.Exit(1)

    try:
        json_path, html_path, history_path = run_hardening_pipeline(
            tool=tool,
            settings=settings,
            llm=llm,
            agent=agent,
            output_dir=output_dir,
            console=console,
            err_console=err_console,
        )
    finally:
        agent.close()


# ── Helper: load tool definition from YAML or JSON ───────────────────────────

def _load_tool_definition(path: Path) -> "MCPToolDefinition":
    from agent_hardener.shared.schemas import MCPToolDefinition

    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")

    if suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    elif suffix == ".json":
        import json
        data = json.loads(text)
    else:
        # Try YAML first, fall back to JSON
        try:
            data = yaml.safe_load(text)
        except Exception:
            import json
            data = json.loads(text)

    # Support either raw MCP format or a wrapped format with a top-level "tool" key
    if "tool" in data and isinstance(data["tool"], dict):
        data = data["tool"]

    return MCPToolDefinition.from_mcp_json(data)


@app.command()
def gateway(
    policy_file: Path = typer.Option(
        ...,
        "--policy", "-p",
        help="Path to a SAMOS policy JSON, a report.json, or a hardening round entry.",
        exists=True, file_okay=True, dir_okay=False, readable=True,
    ),
    agent_endpoint: str = typer.Option(
        ...,
        "--agent-endpoint",
        help="URL of the unprotected agent the gateway will forward to (e.g., http://localhost:8080).",
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8090, "--port", min=1, max=65535, help="Bind port."),
    audit_log: Optional[Path] = typer.Option(
        None, "--audit-log",
        help="Optional JSONL file to append every enforcement event to.",
    ),
    agent_auth_token: str = typer.Option(
        "", "--agent-auth-token",
        help="Bearer token forwarded to the inner agent (defaults to none).",
    ),
) -> None:
    """Launch the SAMOS policy gateway in front of an existing agent endpoint.

    The gateway loads a policy, accepts the same {"prompt": "..."} POST /run
    contract as the underlying agent, and rewrites any tool call the policy
    would block before returning the trajectory to the caller. Enforcement
    decisions are recorded in an in-memory ring (queryable via GET /audit) and
    optionally appended to --audit-log as JSONL.
    """
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        err_console.print(
            "[bold red]ERROR:[/] uvicorn is required to launch the gateway.\n"
            "Install with: [cyan]pip install -e \".[dev]\"[/]"
        )
        raise typer.Exit(1)

    from agent_hardener.gateway_server import create_app

    try:
        app_instance = create_app(
            policy_path=policy_file,
            agent_endpoint=agent_endpoint,
            agent_auth_token=agent_auth_token,
            audit_log_path=audit_log,
        )
    except Exception as exc:
        err_console.print(f"[bold red]ERROR loading policy or building app:[/] {exc}")
        raise typer.Exit(1)

    policy_tool = app_instance.state.policy.tool_name
    n_rules = len(app_instance.state.policy.enforcement_rules)

    console.print(Panel(
        f"[bold cyan]agent-hardener gateway[/] [dim]v{__version__}[/]\n\n"
        f"  [bold]Policy:[/]         {policy_file}\n"
        f"  [bold]Protected tool:[/] [cyan]{policy_tool}[/]\n"
        f"  [bold]Enforcement:[/]    {n_rules} rule(s) loaded\n"
        f"  [bold]Inner agent:[/]    {agent_endpoint}\n"
        f"  [bold]Audit log:[/]      {audit_log if audit_log else '(in-memory only)'}\n"
        f"  [bold]Listening:[/]      [green]http://{host}:{port}[/]\n\n"
        f"  [dim]Endpoints:[/] [cyan]POST /run[/]  [cyan]GET /health[/]  "
        f"[cyan]GET /policy[/]  [cyan]GET /audit[/]  [cyan]POST /tools/list[/]",
        border_style="cyan",
        padding=(1, 2),
    ))

    import uvicorn
    uvicorn.run(app_instance, host=host, port=port, log_level="info")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
