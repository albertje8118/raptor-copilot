---
description: Full autonomous security workflow — scan, validate, analyse, group, consensus, exploit, patch
---

# /agentic - RAPTOR Full Autonomous Workflow

🤖 **AGENTIC MODE** - This will autonomously:
1. Scan code with Semgrep/CodeQL
2. Analyze each finding with LLM (parallel dispatch)
3. **Generate exploit PoCs** for exploitable findings
4. **Generate secure patches** for confirmed vulnerabilities
5. **Cross-finding analysis** (structural grouping, shared root causes)

Nothing will be applied to your code - only generated in out/ directory.

Execute: `python3 raptor.py agentic --repo <path>`

## How analysis works

Phase 4 dispatches findings for parallel analysis via one of two paths:

- **GitHub Copilot CLI on PATH**: dispatches `copilot` CLI subprocesses for structured analysis
- **External LLM configured**: dispatches via `generate_structured()` API calls
- **Both available**: uses the external LLM first, then falls back to GitHub Copilot CLI if it fails

Model roles determine which model analyses (analysis), writes code (code), and
provides second opinions (consensus).

If **neither** is available, Phase 4 cannot run. The pipeline produces prep-only
output. In that case, **YOU (the interactive assistant) are the LLM** — the user may ask you
to analyse the findings directly in conversation. See the prep_only report mode
below for instructions.

After per-finding analysis: structural grouping identifies related findings,
group analysis explains shared patterns, and consensus (if configured) flags
disputed verdicts. Cost tracking is real-time with adaptive budget cutoff.

## Report modes

The pipeline produces a report with one of three modes:

**`"mode": "prep_only"`** — No LLM was available and orchestration did not run.
The pipeline completed scanning, SARIF parsing, deduplication, code reading,
dataflow extraction, and structured output — but no analysis. Read the findings
from `autonomous_analysis_report.json` in the output directory. Each finding
includes `code`, `surrounding_context`, `file_path`, line numbers, `dataflow`,
and `feasibility`. If the user asks you to analyse them, for each finding:

1. **Analyse** — is it a true positive? Is it exploitable? What's the attack scenario?
2. **Generate exploit PoCs** for exploitable findings
3. **Generate secure patches** for confirmed vulnerabilities

Do NOT include raw code from the findings in sub-agent prompts — let each agent
read the code itself via the Read tool.

**`"mode": "full"`** — An external LLM performed sequential analysis in Phase 3
(when GitHub Copilot CLI orchestration was not used). Present the results to the user.

**`"mode": "orchestrated"`** — Phase 4 performed parallel analysis via external
LLM or GitHub Copilot CLI dispatches. Results include per-finding `analysed_by` (which
model), `cost_usd`, `duration_seconds`, plus `cross_finding_groups` and optional
`consensus` data. Present the results to the user.

In all modes, findings are in the `results` array of the report. Orchestrated
and full mode findings include `is_exploitable`, `reasoning`, `exploit_code`, and
`patch_code` fields. Prep-only findings include `code`, `surrounding_context`,
`dataflow`, and `feasibility` for review.
