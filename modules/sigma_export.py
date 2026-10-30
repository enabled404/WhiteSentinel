"""
modules/sigma_export.py — cycle 3 defensive layer.

Sigma rule-pack export: turns detection_data stubs into one YAML file per
technique, running the validation gate (modules/sigma_validate.py) BEFORE
writing each file. Warn mode (default) reports issues and still writes;
strict mode skips any rule the gate flags as invalid.

YAML is emitted by hand: the project has no PyYAML dependency, and the
stub dicts contain only strings, ints, lists, and nested mappings, which
a small emitter covers exactly. The gate validates rule DICTS, never
YAML text, so no YAML parser is needed on this path.
"""
from __future__ import annotations

import os

from modules.detection_data import DETECTION_DATA, sigma_stub_for
from modules.mitre_data import TECHNIQUES
from modules.sigma_validate import validate_rule


def _yaml_scalar(value) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    needs_quote = (
        not text
        or text[0] in "!&*?|>%@`\"'"
        or text.endswith(":")
        or ": " in text
        or " #" in text
        or text.strip() != text
    )
    if needs_quote:
        return "'" + text.replace("'", "''") + "'"
    return text


def _emit_yaml(value, indent: int = 0) -> list[str]:
    pad = " " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, val in value.items():
            if isinstance(val, (dict, list)) and val:
                lines.append(f"{pad}{key}:")
                lines.extend(_emit_yaml(val, indent + 2))
            elif isinstance(val, list):
                lines.append(f"{pad}{key}: []")
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(val)}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}-")
                lines.extend(_emit_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
    else:
        lines.append(f"{pad}{_yaml_scalar(value)}")
    return lines


def rule_to_yaml(rule: dict) -> str:
    """Serialize one rule dict to a YAML document string."""
    return "\n".join(_emit_yaml(rule)) + "\n"


def export_rules(technique_ids: list[str] | None = None,
                 output_dir: str = "",
                 strict: bool = False) -> dict:
    """Export Sigma stubs for techniques to YAML files.

    technique_ids None means every technique with detection data.
    Returns {"written": [...], "blocked": [...], "warnings": {...}} with
    paths, gate blocks (strict mode only), and per-rule warnings.
    Unknown technique IDs are reported and skipped, never written.
    """
    ids = sorted(technique_ids) if technique_ids else \
        sorted(DETECTION_DATA)
    written: list[str] = []
    blocked: list[str] = []
    warnings: dict[str, list[str]] = {}
    unknown: list[str] = []
    os.makedirs(output_dir, exist_ok=True) if output_dir else None
    for tid in ids:
        stub = sigma_stub_for(tid)
        if stub is None:
            unknown.append(tid)
            continue
        verdict = validate_rule(stub, strict=strict)
        if verdict["warnings"]:
            warnings[tid] = verdict["warnings"]
        if verdict["blocked"]:
            blocked.append(tid)
            continue
        if not output_dir:
            written.append(f"<dry-run> {tid}")
            continue
        fname = f"sigma_{tid.lower().replace('.', '_')}.yml"
        path = os.path.join(output_dir, fname)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(rule_to_yaml(stub))
        written.append(path)
    return {
        "written": written,
        "blocked": blocked,
        "warnings": warnings,
        "unknown": unknown,
        "techniques_total": len(ids),
    }


def rule_pack_for_findings(findings: list[dict]) -> list[str]:
    """Technique IDs observed in findings, for report-time export."""
    seen = []
    for f in findings:
        for tid in f.get("mitre_ids", []) or []:
            if tid in TECHNIQUES and tid not in seen:
                seen.append(tid)
    return sorted(seen)
