"""Backward-compatible re-export for GitHub Copilot CLI dispatch."""

from .copilot_dispatch import (  # noqa: F401
    DEFAULT_COPILOT_MODEL,
    SUPPORTED_COPILOT_MODELS,
    build_finding_prompt,
    build_schema,
    invoke_cc_simple,
    invoke_copilot_simple,
    parse_cc_freeform,
    parse_cc_result,
    parse_copilot_freeform,
    parse_copilot_result,
    resolve_copilot_model,
    write_debug,
)

__all__ = [
    "DEFAULT_COPILOT_MODEL",
    "SUPPORTED_COPILOT_MODELS",
    "build_finding_prompt",
    "build_schema",
    "invoke_cc_simple",
    "invoke_copilot_simple",
    "parse_cc_freeform",
    "parse_cc_result",
    "parse_copilot_freeform",
    "parse_copilot_result",
    "resolve_copilot_model",
    "write_debug",
]
