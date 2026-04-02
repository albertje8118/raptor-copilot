#!/usr/bin/env python3
"""
RAPTOR Orchestrator — Phase 4 of the /agentic workflow.

Dispatches structured findings from Phase 3 for parallel vulnerability
analysis, exploit generation, patch creation, consensus, and retry.

Dispatch routing:
  - External LLM configured: parallel generate_structured() / generate()
  - No external LLM + copilot on PATH: GitHub Copilot CLI subprocesses
  - Neither: return None (manual review)

If external LLM fails entirely, falls back to GitHub Copilot CLI automatically.
"""

import copy
import json
import logging
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from packages.llm_analysis.copilot_dispatch import invoke_copilot_simple
from packages.llm_analysis.dispatch import _format_elapsed

logger = logging.getLogger(__name__)

# Adaptive cutoff thresholds (percentage of max_cost_per_scan)
CUTOFF_SKIP_CONSENSUS = 0.70
CUTOFF_SKIP_EXPLOITS = 0.85
CUTOFF_SINGLE_MODEL = 0.95


class CostTracker:
    """Thread-safe cost tracking with adaptive budget cutoff.

    Aggregates costs from external LLM calls and GitHub Copilot CLI dispatches.
    Copilot CLI dispatches currently report zero incremental cost. Provides budget-aware
    cutoff signals.
    """

    def __init__(self, max_cost: float = 0.0):
        self._lock = threading.RLock()  # Reentrant — get_summary calls _budget_ratio
        self._total_cost = 0.0
        self._total_tokens = 0
        self._thinking_tokens = 0
        self._max_cost = max_cost  # 0 = no limit
        self._per_model: Dict[str, float] = {}

    def add_cost(self, model_name: str, cost: float, tokens: int = 0,
                 thinking_tokens: int = 0) -> None:
        """Record cost and tokens from any source (thread-safe)."""
        with self._lock:
            self._total_cost += cost
            self._total_tokens += tokens
            self._thinking_tokens += thinking_tokens
            self._per_model[model_name] = self._per_model.get(model_name, 0.0) + cost

    @property
    def total_cost(self) -> float:
        with self._lock:
            return self._total_cost

    def _budget_ratio(self) -> float:
        """Current spend as fraction of budget. 0 if no budget set."""
        if self._max_cost <= 0:
            return 0.0
        with self._lock:
            return self._total_cost / self._max_cost

    def should_skip_consensus(self) -> bool:
        return self._budget_ratio() >= CUTOFF_SKIP_CONSENSUS

    def should_skip_exploits(self) -> bool:
        return self._budget_ratio() >= CUTOFF_SKIP_EXPLOITS

    def should_single_model(self) -> bool:
        return self._budget_ratio() >= CUTOFF_SINGLE_MODEL

    def should_skip_phase(self, n_calls: int, model_name: str,
                          cutoff_ratio: float, phase_name: str) -> bool:
        """Pre-check: would running this phase likely exceed the budget?

        Prevents starting a parallel dispatch that would be mostly cancelled
        by per-call cutoffs. Analysis dispatch never uses this (always runs).
        """
        if self._max_cost <= 0:
            return False
        estimate = self.estimate_cost(n_calls, model_name=model_name)
        with self._lock:
            projected = self._total_cost + estimate
        if projected > self._max_cost * cutoff_ratio:
            logger.info(f"Skipping {phase_name} — estimated ${estimate:.2f} "
                        f"would push total to ${projected:.2f} (budget: ${self._max_cost:.2f})")
            return True
        return False

    def estimate_cost(self, n_findings: int, n_consensus_models: int = 0,
                       model_name: str = "", is_copilot: bool = False) -> float:
        """Estimate total cost before dispatch (informational).

        Uses MODEL_COSTS for external LLMs. GitHub Copilot CLI dispatches
        are treated as zero incremental cost because RAPTOR cannot obtain
        per-call billing data from the CLI.
        """
        if is_copilot:
            avg_cost = 0.0
        else:
            from packages.llm_analysis.llm.model_data import MODEL_COSTS
            # Estimate ~2K input tokens + ~500 output tokens per analysis call
            rates = MODEL_COSTS.get(model_name, {})
            if rates:
                avg_cost = (2.0 * rates.get("input", 0.003)) + (0.5 * rates.get("output", 0.015))
            else:
                avg_cost = 0.03  # Conservative default

        analysis_calls = n_findings
        consensus_calls = n_findings * n_consensus_models
        return (analysis_calls + consensus_calls) * avg_cost

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            summary = {
                "total_cost": round(self._total_cost, 4),
                "total_tokens": self._total_tokens,
                "max_cost": self._max_cost,
                "budget_used_percent": round(self._budget_ratio() * 100, 1) if self._max_cost > 0 else 0,
                "cost_by_model": {k: round(v, 4) for k, v in self._per_model.items()},
            }
            if self._thinking_tokens > 0:
                summary["thinking_tokens"] = self._thinking_tokens
            return summary


def orchestrate(
    prep_report_path: Path,
    repo_path: Path,
    out_dir: Path,
    max_parallel: int = 3,
    no_exploits: bool = False,
    no_patches: bool = False,
    llm_config: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """Orchestrate vulnerability analysis via external LLM or GitHub Copilot CLI.

    Called from raptor_agentic.py Phase 4. Dispatches findings for parallel
    analysis, runs structural grouping, and optionally runs consensus and
    group analysis.

    Dispatch routing:
    - llm_config provided (external LLM) -> parallel generate_structured()
    - llm_config None + copilot on PATH -> Copilot CLI subprocesses
    - Neither -> return None

    If external LLM dispatch fails entirely, falls back to Copilot CLI.

    Args:
        prep_report_path: Path to autonomous_analysis_report.json from Phase 3.
        repo_path: Target repository path.
        out_dir: Output directory for orchestration results.
        max_parallel: Maximum concurrent agents.
        no_exploits: Skip exploit generation.
        no_patches: Skip patch generation.
        llm_config: LLMConfig for external LLM dispatch (None = Copilot CLI only).

    Returns:
        Orchestrated report dict, or None if orchestration was skipped.
    """
    # Load Phase 3 report
    try:
        report = json.loads(prep_report_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read Phase 3 report: {e}")
        print(f"\n  Failed to read analysis report: {e}")
        return None

    if report.get("mode") != "prep_only":
        logger.info("Phase 3 ran full analysis — orchestration not needed")
        return None

    findings = report.get("results", [])
    if not findings:
        print("\n  No findings to analyse")
        return None

    # Resolve model roles
    from packages.llm_analysis.llm.config import resolve_model_roles
    role_resolution = {"analysis_model": None, "code_model": None,
                       "consensus_models": [], "fallback_models": []}
    if llm_config and llm_config.primary_model:
        role_resolution = resolve_model_roles(
            llm_config.primary_model,
            llm_config.fallback_models if hasattr(llm_config, 'fallback_models') else [],
        )

    # Cost tracking
    max_cost = getattr(llm_config, 'max_cost_per_scan', 0) if llm_config else 0
    cost_tracker = CostTracker(max_cost=max_cost or 0)

    # Estimate and print cost
    n_consensus = len(role_resolution.get("consensus_models", []))
    analysis_model_name = role_resolution.get("analysis_model").model_name if role_resolution.get("analysis_model") else ""
    is_copilot_dispatch = not (llm_config and llm_config.primary_model)
    estimate = cost_tracker.estimate_cost(len(findings), n_consensus,
                                          model_name=analysis_model_name, is_copilot=is_copilot_dispatch)
    if estimate > 0:
        print(f"\n  Estimated cost: ~${estimate:.2f} for {len(findings)} findings"
              + (f" + {n_consensus} consensus model(s)" if n_consensus else ""))

    # --- Build dispatch callable ---
    from packages.llm_analysis.dispatch import dispatch_task, DispatchResult
    from packages.llm_analysis.tasks import (
        AnalysisTask, ExploitTask, PatchTask, ConsensusTask, GroupAnalysisTask,
        RetryTask,
    )

    dispatch_mode = "none"
    dispatch_fn = None
    start_time = time.monotonic()

    if llm_config and llm_config.primary_model:
        # External LLM: dispatch via generate_structured/generate
        from packages.llm_analysis.llm.client import LLMClient
        client = LLMClient(llm_config)

        def dispatch_fn(prompt, schema, system_prompt, temperature, model):
            if schema:
                response = client.generate_structured(
                    prompt=prompt, schema=schema, system_prompt=system_prompt,
                    model_config=model, temperature=temperature,
                )
                return DispatchResult(
                    result=response.result, cost=response.cost,
                    tokens=response.tokens_used, model=response.model,
                    duration=response.duration,
                )
            else:
                response = client.generate(
                    prompt=prompt, system_prompt=system_prompt,
                    model_config=model, temperature=temperature,
                )
                return DispatchResult(
                    result={"content": response.content}, cost=response.cost,
                    tokens=response.tokens_used, model=response.model,
                    duration=response.duration,
                )

        dispatch_mode = "external_llm"
    else:
        copilot_bin = shutil.which("copilot")
        if not copilot_bin:
            print("\n  copilot not found on PATH — cannot dispatch sub-agents")
            print("  Install GitHub Copilot CLI and ensure `copilot` is on PATH.")
            return None

        def dispatch_fn(prompt, schema, system_prompt, temperature, model):
            return invoke_copilot_simple(prompt, schema, repo_path, copilot_bin, out_dir, model=model)

        dispatch_mode = "copilot_cli"

    # --- Per-finding analysis ---
    results_by_id = {}
    analysis_results = dispatch_task(
        AnalysisTask(), findings, dispatch_fn, role_resolution,
        results_by_id, cost_tracker, max_parallel,
    )

    # Fallback: if external LLM failed entirely, try GitHub Copilot CLI
    if (dispatch_mode == "external_llm"
            and analysis_results
            and all("error" in r for r in analysis_results)):
        copilot_bin = shutil.which("copilot")
        if copilot_bin:
            print("\n  All external LLM calls failed — falling back to GitHub Copilot CLI")
            dispatch_mode = "copilot_cli_fallback"

            def dispatch_fn(prompt, schema, system_prompt, temperature, model):
                return invoke_copilot_simple(prompt, schema, repo_path, copilot_bin, out_dir, model=model)

            analysis_results = dispatch_task(
                AnalysisTask(), findings, dispatch_fn, role_resolution,
                results_by_id, cost_tracker, max_parallel,
            )

    # Index results for downstream tasks
    for r in analysis_results:
        fid = r.get("finding_id")
        if fid:
            results_by_id[fid] = r

    # --- Exploit/patch generation ---
    # Copilot CLI analysis may produce exploits/patches inline via schema. ExploitTask/PatchTask
    # only select findings that are exploitable AND missing exploit_code/patch_code,
    # so this is a no-op when the CLI already generated them.
    if not no_exploits:
        dispatch_task(
            ExploitTask(), findings, dispatch_fn, role_resolution,
            results_by_id, cost_tracker, max_parallel,
        )

    if not no_patches:
        dispatch_task(
            PatchTask(), findings, dispatch_fn, role_resolution,
            results_by_id, cost_tracker, max_parallel,
        )

    # --- Consensus (if configured, skip retry) ---
    consensus_models = role_resolution.get("consensus_models", [])
    if consensus_models:
        dispatch_task(
            ConsensusTask(), findings, dispatch_fn, role_resolution,
            results_by_id, cost_tracker, max_parallel,
        )
    else:
        # Retry low-confidence findings (only when no consensus)
        dispatch_task(
            RetryTask(), findings, dispatch_fn, role_resolution,
            results_by_id, cost_tracker, max_parallel,
        )

    elapsed = time.monotonic() - start_time

    # --- Structural grouping (pure Python, no LLM) ---
    groups = _structural_grouping(findings)
    if groups:
        n = len(groups)
        print(f"\n  Structural grouping: {n} group{'s' if n != 1 else ''} found")

    # --- Group analysis ---
    group_task = GroupAnalysisTask(results_by_id=results_by_id)
    group_results = dispatch_task(
        group_task, groups, dispatch_fn, role_resolution,
        results_by_id, cost_tracker, max_parallel,
    )
    group_analyses = {}
    for r in group_results:
        gid = r.get("finding_id")  # group_id comes through as finding_id
        if gid and "error" not in r:
            group_analyses[gid] = r

    # --- Merge and write ---
    per_finding_results = list(results_by_id.values())
    merged = _merge_results(report, per_finding_results,
                            no_exploits=no_exploits, no_patches=no_patches)
    merged["cross_finding_groups"] = groups
    if group_analyses:
        merged["group_analyses"] = group_analyses

    consensus_disputes = sum(1 for r in per_finding_results
                             if r.get("consensus") == "disputed")
    retries = sum(1 for r in per_finding_results if r.get("retried"))
    low_confidence = sum(1 for r in per_finding_results if r.get("low_confidence"))

    merged["orchestration"] = {
        "mode": dispatch_mode,
        "analysis_model": (role_resolution.get("analysis_model").model_name
                          if role_resolution.get("analysis_model") else None),
        "consensus_models": [m.model_name for m in consensus_models],
        "findings_dispatched": len(findings),
        "findings_analysed": sum(1 for r in per_finding_results if "error" not in r),
        "findings_failed": sum(1 for r in per_finding_results if "error" in r),
        "structural_groups": len(groups),
        "consensus_disputes": consensus_disputes,
        "low_confidence_retries": retries,
        "low_confidence_remaining": low_confidence,
        "group_analyses": len(group_analyses),
        "elapsed_seconds": round(elapsed, 1),
        "max_parallel": max_parallel,
        "cost": cost_tracker.get_summary(),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "orchestrated_report.json"
    out_path.write_text(json.dumps(merged, indent=2))
    logger.info(f"Orchestrated report saved to {out_path}")

    # Summary
    orch = merged["orchestration"]
    cost_total = orch["cost"]["total_cost"]
    print(f"\n  Orchestration complete: {orch['findings_analysed']} analysed, "
          f"{orch['findings_failed']} failed, {_format_elapsed(orch['elapsed_seconds'])} elapsed"
          + (f", ${cost_total:.2f}" if cost_total > 0 else ""))
    if groups:
        print(f"  Cross-finding groups: {len(groups)}")
    print(f"  Report: {out_path}")

    return merged


def _merge_results(
    prep_report: Dict[str, Any],
    cli_results: List[Dict[str, Any]],
    no_exploits: bool = False,
    no_patches: bool = False,
) -> Dict[str, Any]:
    """Merge GitHub Copilot CLI results back into the prep report.

    Matches by finding_id. CLI results update analysis fields while
    preserving all prep data (code, dataflow, feasibility).
    """
    merged = dict(prep_report)
    merged["mode"] = "orchestrated"

    # Index CLI results by finding_id
    cli_by_id = {}
    for r in cli_results:
        fid = r.get("finding_id")
        if fid:
            cli_by_id[fid] = r

    # Deep copy results so we don't mutate the caller's data
    results = copy.deepcopy(merged.get("results", []))

    # Merge into findings
    analysed = 0
    exploitable = 0
    exploits_generated = 0
    patches_generated = 0

    for finding in results:
        fid = finding.get("finding_id")
        cli_result = cli_by_id.get(fid)
        if not cli_result or "error" in cli_result:
            # No CLI result or failed — keep prep data, mark as unanalysed
            finding["copilot_error"] = cli_result.get("error") if cli_result else "not dispatched"
            if cli_result and cli_result.get("copilot_debug_file"):
                finding["copilot_debug_file"] = cli_result["copilot_debug_file"]
            continue

        analysed += 1

        # Copy non-internal keys from dispatch result to finding.
        # Underscore-prefixed keys are internal and stripped.
        # Keys already in finding (prep data) are NOT overwritten — defence
        # against prompt injection where LLM returns crafted field names.
        for k, v in cli_result.items():
            if k.startswith("_") or k == "finding_id":
                continue
            if k not in finding:
                finding[k] = v

        # Ensure standard fields are set
        finding["exploitable"] = cli_result.get("is_exploitable", False)
        finding["exploitability_score"] = cli_result.get("exploitability_score", 0)

        if finding["exploitable"]:
            exploitable += 1

        if finding["exploitable"] and not no_exploits and cli_result.get("exploit_code"):
            finding["has_exploit"] = True
            exploits_generated += 1
        else:
            finding.pop("exploit_code", None)
            finding["has_exploit"] = False

        if finding["exploitable"] and not no_patches and cli_result.get("patch_code"):
            finding["has_patch"] = True
            patches_generated += 1
        else:
            finding.pop("patch_code", None)
            finding["has_patch"] = False

    merged["results"] = results
    merged["analyzed"] = analysed
    merged["exploitable"] = exploitable
    merged["exploits_generated"] = exploits_generated
    merged["patches_generated"] = patches_generated

    return merged


def _structural_grouping(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group related findings by structural similarity. Pure Python, no LLM.

    Direct grouping only — no transitive closure. A finding can appear in
    multiple overlapping groups. Each group has one specific shared criterion.

    Returns list of groups, each with:
        group_id, criterion, criterion_value, finding_ids
    Groups of size 1 are excluded.
    """
    groups = []
    group_counter = 0

    def _add_group(criterion: str, value: str, finding_ids: List[str]):
        nonlocal group_counter
        if len(finding_ids) >= 2:
            group_counter += 1
            groups.append({
                "group_id": f"GRP-{group_counter:03d}",
                "criterion": criterion,
                "criterion_value": value,
                "finding_ids": sorted(finding_ids),
            })

    # Index findings
    findings_by_id = {}
    for r in results:
        fid = r.get("finding_id")
        if fid:
            findings_by_id[fid] = r

    # Group by same file path
    by_file: Dict[str, List[str]] = {}
    for fid, r in findings_by_id.items():
        fp = r.get("file_path", "")
        if fp:
            by_file.setdefault(fp, []).append(fid)
    for fp, fids in by_file.items():
        _add_group("file_path", fp, fids)

    # Group by same rule ID (skip rules that match >50% of findings — too generic)
    by_rule: Dict[str, List[str]] = {}
    for fid, r in findings_by_id.items():
        rule = r.get("rule_id", "")
        if rule:
            by_rule.setdefault(rule, []).append(fid)
    half = len(findings_by_id) / 2
    by_rule = {r: fids for r, fids in by_rule.items() if len(fids) <= half}
    for rule, fids in by_rule.items():
        _add_group("rule_id", rule, fids)

    # Group by shared sanitiser location
    by_sanitiser: Dict[str, List[str]] = {}
    for fid, r in findings_by_id.items():
        dataflow = r.get("dataflow") or {}
        for san in dataflow.get("sanitizers_found", []):
            if isinstance(san, dict):
                loc = f"{san.get('file', '?')}:{san.get('line', '?')}"
            else:
                loc = str(san)
            by_sanitiser.setdefault(loc, []).append(fid)
    for loc, fids in by_sanitiser.items():
        _add_group("sanitiser", loc, fids)

    # Group by same dataflow source
    by_source: Dict[str, List[str]] = {}
    for fid, r in findings_by_id.items():
        dataflow = r.get("dataflow") or {}
        source = dataflow.get("source", {})
        if source:
            loc = f"{source.get('file', '?')}:{source.get('line', '?')}"
            by_source.setdefault(loc, []).append(fid)
    for loc, fids in by_source.items():
        _add_group("dataflow_source", loc, fids)

    # Group by shared dataflow references (any file:line in common)
    # Inverted index: ref -> set of finding_ids. O(N*R) instead of O(N²).
    ref_to_fids: Dict[str, set] = {}
    for fid, r in findings_by_id.items():
        dataflow = r.get("dataflow") or {}
        source = dataflow.get("source", {})
        if source:
            ref = f"{source.get('file', '?')}:{source.get('line', '?')}"
            ref_to_fids.setdefault(ref, set()).add(fid)
        for step in dataflow.get("steps", []):
            ref = f"{step.get('file', '?')}:{step.get('line', '?')}"
            ref_to_fids.setdefault(ref, set()).add(fid)
        sink = dataflow.get("sink", {})
        if sink:
            ref = f"{sink.get('file', '?')}:{sink.get('line', '?')}"
            ref_to_fids.setdefault(ref, set()).add(fid)

    for ref, fids_set in ref_to_fids.items():
        _add_group("shared_dataflow_ref", ref, list(fids_set))

    return groups
