"""GitHub Copilot CLI subprocess dispatch internals.

Handles invoking `copilot -p` subprocesses, parsing JSON output,
building prompts and schemas for Copilot CLI, and writing debug files.

Used by orchestrator.py via invoke_copilot_simple as a dispatch_fn callable.
"""

import copy
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from packages.llm_analysis.dispatch import DispatchResult
from packages.llm_analysis.prompts.schemas import FINDING_RESULT_SCHEMA

logger = logging.getLogger(__name__)

COPILOT_TIMEOUT = 300  # 5 minutes per finding
DEFAULT_COPILOT_MODEL = "gpt-5.4"
SUPPORTED_COPILOT_MODELS = ("gpt-5.4", "claude-sonnet-4.6")


def _normalise_copilot_model(model_name: Optional[str]) -> Optional[str]:
    """Normalize supported GitHub Copilot CLI model names."""
    if not model_name:
        return None
    normalized = model_name.strip().lower().replace("_", "-")
    aliases = {
        "claude sonnet 4.6": "claude-sonnet-4.6",
        "claude-sonnet-4-6": "claude-sonnet-4.6",
        "claude sonnet 4-6": "claude-sonnet-4.6",
        "gpt 5.4": "gpt-5.4",
        "gpt-5-4": "gpt-5.4",
    }
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in SUPPORTED_COPILOT_MODELS else None


def resolve_copilot_model(model=None) -> str:
    """Resolve the GitHub Copilot CLI model to use for a dispatch."""
    requested = getattr(model, "model_name", None) if model is not None else None
    env_override = os.getenv("RAPTOR_COPILOT_MODEL")
    selected = (
        _normalise_copilot_model(requested)
        or _normalise_copilot_model(env_override)
        or DEFAULT_COPILOT_MODEL
    )
    if requested and not _normalise_copilot_model(requested):
        logger.warning(
            "GitHub Copilot CLI model '%s' is not supported by RAPTOR; falling back to %s",
            requested,
            selected,
        )
    return selected


def invoke_copilot_simple(
    prompt,
    schema,
    repo_path,
    copilot_bin,
    out_dir,
    timeout=COPILOT_TIMEOUT,
    model=None,
):
    """GitHub Copilot CLI invocation with pre-built prompt. Returns DispatchResult."""
    selected_model = resolve_copilot_model(model)
    cmd = [
        copilot_bin,
        "-s",
        "--model",
        selected_model,
        "-p",
        prompt,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=repo_path,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return DispatchResult(result={"error": f"timeout after {timeout}s"})

    if proc.returncode != 0:
        stderr_excerpt = (proc.stderr or "")[:500]
        result = {"error": f"exit code {proc.returncode}: {stderr_excerpt}"}
        write_debug(out_dir, "dispatch", proc.stdout, proc.stderr, result)
        return DispatchResult(result=result, model=selected_model)

    if schema:
        parsed = parse_copilot_result(
            proc.stdout, proc.stderr, "unknown", default_model=selected_model
        )
    else:
        parsed = parse_copilot_freeform(
            proc.stdout, proc.stderr, default_model=selected_model
        )

    cost = parsed.pop("cost_usd", 0)
    tokens = parsed.pop("_tokens", 0)
    used_model = parsed.pop("analysed_by", selected_model)
    duration = parsed.pop("duration_seconds", 0)

    return DispatchResult(
        result=parsed,
        cost=cost,
        tokens=tokens,
        model=used_model,
        duration=duration,
    )


def write_debug(
    out_dir: Path,
    finding_id: str,
    stdout: str,
    stderr: str,
    result: Dict[str, Any],
) -> None:
    """Write raw Copilot CLI output to a debug file on failure."""
    try:
        debug_dir = out_dir / "debug"
        debug_dir.mkdir(parents=True, exist_ok=True)
        debug_file = debug_dir / f"copilot_{finding_id}.txt"
        debug_file.write_text(
            f"STDOUT:\n{stdout or '(empty)'}\n\nSTDERR:\n{stderr or '(empty)'}"
        )
        result["copilot_debug_file"] = f"debug/copilot_{finding_id}.txt"
    except OSError:
        pass


def build_schema(no_exploits: bool = False, no_patches: bool = False) -> Dict[str, Any]:
    """Build JSON Schema for Copilot CLI output, excluding disabled fields."""
    schema = copy.deepcopy(FINDING_RESULT_SCHEMA)
    if no_exploits:
        schema["properties"].pop("exploit_code", None)
    if no_patches:
        schema["properties"].pop("patch_code", None)
    return schema


def build_finding_prompt(
    finding: Dict[str, Any],
    no_exploits: bool = False,
    no_patches: bool = False,
) -> str:
    """Build a lightweight prompt for a GitHub Copilot CLI analysis run."""
    finding_id = finding.get("finding_id", "unknown")
    rule_id = finding.get("rule_id", "unknown")
    file_path = finding.get("file_path", "unknown")
    start_line = finding.get("start_line", "?")
    end_line = finding.get("end_line", start_line)
    message = finding.get("message", "")
    level = finding.get("level", "warning")

    prompt = f"""You are a security researcher analysing a potential vulnerability.

## Finding
- ID: {finding_id}
- Rule: {rule_id}
- Severity: {level}
- File: {file_path}
- Lines: {start_line}-{end_line}
- Description: {message}
"""

    dataflow = finding.get("dataflow")
    if dataflow:
        source = dataflow.get("source", {})
        sink = dataflow.get("sink", {})
        steps = dataflow.get("steps", [])
        sanitizers = dataflow.get("sanitizers_found", [])

        prompt += f"""
## Dataflow path
- Source: {source.get('file', '?')}:{source.get('line', '?')} ({source.get('label', '')})
- Sink: {sink.get('file', '?')}:{sink.get('line', '?')} ({sink.get('label', '')})
- Intermediate steps: {len(steps)}
- Sanitizers found: {len(sanitizers)}
"""
        if sanitizers:
            prompt += (
                "- Sanitizer locations: "
                + ", ".join(
                    f"{s.get('file', '?')}:{s.get('line', '?')}"
                    for s in sanitizers
                    if isinstance(s, dict)
                )
                + "\n"
            )

    feasibility = finding.get("feasibility")
    if feasibility:
        verdict = feasibility.get("verdict", "unknown")
        chain_breaks = feasibility.get("chain_breaks", [])
        what_would_help = feasibility.get("what_would_help", [])
        prompt += f"""
## Exploit feasibility analysis (from upstream validation pipeline)
This finding has already been through automated feasibility analysis.
The constraints below were empirically verified — treat them as ground truth.
Focus your analysis on attack paths that work within these constraints.

- Verdict: {verdict}
"""
        if chain_breaks:
            prompt += "- Techniques that WON'T work (verified blockers):\n"
            for cb in chain_breaks:
                prompt += f"  - {cb}\n"
        if what_would_help:
            prompt += "- Viable approaches to consider:\n"
            for wh in what_would_help:
                prompt += f"  - {wh}\n"

    prompt += """
## Your task

Inspect the repository files in the current working directory, starting with
the file path above. Examine the surrounding context, imports, and any
functions called in the vulnerable code.

1. **Analyse**: Is this a true positive? Is it exploitable in practice?
   What would an attacker need? What's the real-world impact?
   Rate exploitability_score from 0.0 (impossible) to 1.0 (trivial).
"""

    if not no_exploits:
        prompt += """
2. **Exploit**: If exploitable, write a proof-of-concept exploit.
   The exploit should be practical and demonstrate the vulnerability.
   Include clear comments explaining the attack.
"""

    if not no_patches:
        prompt += f"""
{"3" if not no_exploits else "2"}. **Patch**: Create a secure fix
   that preserves existing functionality.
   Inspect the full file for context before writing the patch.
"""

    prompt += f"""
Return your analysis as structured JSON with finding_id "{finding_id}".
If you cannot complete the task, still return valid JSON with an "error" field.
"""

    return prompt


def _extract_envelope_metadata(
    envelope: dict, into: dict, default_model: Optional[str] = None
) -> None:
    """Extract provider metadata when CLI output includes an envelope."""
    if envelope.get("total_cost_usd"):
        into["cost_usd"] = envelope["total_cost_usd"]
    if envelope.get("duration_ms"):
        into["duration_seconds"] = round(envelope["duration_ms"] / 1000, 1)
    if envelope.get("model"):
        into["analysed_by"] = envelope["model"]
    model_usage = envelope.get("modelUsage", {})
    if "analysed_by" not in into and model_usage:
        into["analysed_by"] = next(iter(model_usage))
    usage = envelope.get("usage", {})
    tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
    if tokens:
        into["_tokens"] = tokens
    into.setdefault("analysed_by", default_model or DEFAULT_COPILOT_MODEL)


def _parse_json_candidate(content: str) -> Optional[Dict[str, Any]]:
    """Parse a direct or substring JSON object if present."""
    decoder = json.JSONDecoder()
    try:
        result = json.loads(content)
        return result if isinstance(result, dict) else None
    except json.JSONDecodeError:
        pass

    start = content.find("{")
    while start != -1:
        try:
            result, _ = decoder.raw_decode(content[start:])
            return result if isinstance(result, dict) else None
        except json.JSONDecodeError:
            start = content.find("{", start + 1)
    return None


def parse_copilot_result(
    stdout: str,
    stderr: str,
    finding_id: str,
    default_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse GitHub Copilot CLI JSON output."""
    content = stdout.strip()
    if not content:
        stderr_excerpt = (stderr or "")[:500]
        return {
            "finding_id": finding_id,
            "analysed_by": default_model or DEFAULT_COPILOT_MODEL,
            "error": f"empty output: {stderr_excerpt}",
        }

    result = _parse_json_candidate(content)
    if result:
        if "structured_output" in result and isinstance(
            result["structured_output"], dict
        ):
            inner = result["structured_output"]
            inner.setdefault("finding_id", finding_id)
            _extract_envelope_metadata(result, inner, default_model=default_model)
            return inner
        result.setdefault("finding_id", finding_id)
        result.setdefault("analysed_by", default_model or DEFAULT_COPILOT_MODEL)
        return result

    if "```" in content:
        parts = content.split("```")
        for part in parts[1::2]:
            lines = part.strip().split("\n", 1)
            candidate = (
                lines[1].strip()
                if len(lines) > 1 and not lines[0].startswith("{")
                else part.strip()
            )
            result = _parse_json_candidate(candidate)
            if result:
                result.setdefault("finding_id", finding_id)
                result.setdefault("analysed_by", default_model or DEFAULT_COPILOT_MODEL)
                return result

    return {
        "finding_id": finding_id,
        "analysed_by": default_model or DEFAULT_COPILOT_MODEL,
        "error": f"could not parse JSON output: {(stderr or content)[:500]}",
    }


def parse_copilot_freeform(
    stdout: str,
    stderr: str,
    default_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse free-form GitHub Copilot CLI output."""
    content = stdout.strip()
    if not content:
        stderr_excerpt = (stderr or "")[:500]
        return {
            "content": "",
            "analysed_by": default_model or DEFAULT_COPILOT_MODEL,
            "error": f"empty output: {stderr_excerpt}",
        }

    parsed = _parse_json_candidate(content)
    if parsed and parsed.get("type") == "result":
        freeform = {
            "content": parsed.get("result", ""),
        }
        _extract_envelope_metadata(parsed, freeform, default_model=default_model)
        return freeform

    return {
        "content": content,
        "analysed_by": default_model or DEFAULT_COPILOT_MODEL,
    }


# Deprecated backward-compatible aliases for older imports.
# Do not use these in new code; prefer the copilot_* names above.
invoke_cc_simple = invoke_copilot_simple
parse_cc_result = parse_copilot_result
parse_cc_freeform = parse_copilot_freeform
