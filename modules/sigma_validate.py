"""
modules/sigma_validate.py — cycle 3 defensive layer.

Sigma rule validation gate. Pure logic, offline: the logsource taxonomy
snapshot below is bundled because offline runs cannot fetch Sigma's
repository. The snapshot will drift as Sigma's taxonomy evolves; treat
unknown products/services/categories as warnings, never as proof a rule
is wrong — custom log sources are legitimate.

Gate semantics (the part that matters):
  - An "error" is structural: a required field is missing, the detection
    block is malformed, the condition references a selection that does
    not exist, or a tag references a technique outside the registry.
  - A "warning" is advisory: unknown logsource product/service/category,
    missing tags, or an unusual status/level value.
  - By default (warn mode) the gate NEVER blocks: it reports and the
    export proceeds. Only strict=True turns errors into a hard block.
    Warnings never block, even in strict mode.
"""
from __future__ import annotations

from modules.mitre_data import TECHNIQUES

REQUIRED_FIELDS = ("title", "id", "status", "description",
                   "logsource", "detection", "level")
VALID_STATUSES = ("stable", "test", "experimental", "deprecated",
                  "unsupported")
VALID_LEVELS = ("informational", "low", "medium", "high", "critical")

# Bundled logsource-taxonomy snapshot (Sigma-style product/service/category).
# Products map to the services Sigma documents for them; categories are the
# generic detection categories. Unknown entries warn, they do not fail.
LOGSOURCE_TAXONOMY: dict[str, dict] = {
    "windows": {
        "services": ("security", "sysmon", "powershell", "wmi", "winrm",
                     "taskscheduler", "printservice-admin", "system",
                     "wmi-activity", "terminalservices-remoteconnectionmanager",
                     "dns-client", "certificate-services", "applocker",
                     "firewall", "bits-client", "codeintegrity-operational"),
        "categories": ("process_creation", "process_access",
                       "network_connection", "file_event", "registry_event",
                       "registry_set", "image_load", "driver_load",
                       "dns_query", "pipe_created"),
    },
    "azure": {
        "services": ("signinlogs", "auditlogs", "activitylogs"),
        "categories": (),
    },
    "linux": {
        "services": ("syslog", "auditd", "auth"),
        "categories": ("process_creation", "network_connection",
                       "file_event"),
    },
    "aws": {
        "services": ("cloudtrail",),
        "categories": (),
    },
    "gcp": {
        "services": ("gcp.audit",),
        "categories": (),
    },
    "macos": {
        "services": ("system", "unified_logging"),
        "categories": ("process_creation", "network_connection",
                       "file_event"),
    },
}


def _tag_technique_ids(rule: dict) -> list[str]:
    """Technique IDs referenced by attack.* tags (lowercased, T-form)."""
    out = []
    for tag in rule.get("tags", []) or []:
        if isinstance(tag, str) and tag.startswith("attack.t"):
            out.append(tag[len("attack."):].upper())
    return out


def validate_rule(rule: dict, strict: bool = False) -> dict:
    """Validate one Sigma rule dict.

    Returns {"valid": bool, "errors": [...], "warnings": [...],
    "blocked": bool}. "valid" is False when any error exists, even in
    warn mode; "blocked" is True only in strict mode with errors.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(rule, dict):
        return {"valid": False, "errors": ["rule is not a mapping"],
                "warnings": [], "blocked": bool(strict)}

    for field in REQUIRED_FIELDS:
        if field not in rule or rule[field] in (None, "", {}, []):
            errors.append(f"missing required field: {field}")

    if "status" in rule and rule["status"] not in VALID_STATUSES:
        warnings.append(f"unusual status value: {rule['status']!r}")
    if "level" in rule and rule["level"] not in VALID_LEVELS:
        errors.append(f"invalid level value: {rule['level']!r}")

    logsource = rule.get("logsource")
    if isinstance(logsource, dict):
        product = logsource.get("product")
        service = logsource.get("service")
        category = logsource.get("category")
        if product and product not in LOGSOURCE_TAXONOMY:
            warnings.append(f"unknown logsource product: {product!r}")
        elif product:
            known = LOGSOURCE_TAXONOMY[product]
            if service and service not in known["services"]:
                warnings.append(
                    f"unknown logsource service for {product}: {service!r}")
            if category and category not in known["categories"]:
                warnings.append(
                    f"unknown logsource category for {product}: {category!r}")
        if not product and not service and not category:
            errors.append("logsource names neither product, service, nor "
                          "category")
    elif logsource is not None:
        errors.append("logsource must be a mapping")

    detection = rule.get("detection")
    if isinstance(detection, dict):
        condition = detection.get("condition")
        if not condition:
            errors.append("detection is missing a condition")
        else:
            selections = {k for k in detection if k != "condition"}
            # Condition references: bare selection names and "1 of X" forms.
            import re
            refs = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*",
                                  str(condition)))
            refs -= {"of", "all", "them", "and", "or", "not"}
            for ref in refs:
                if ref.startswith("selection") and ref not in selections:
                    errors.append(
                        f"condition references unknown selection: {ref}")
                elif ref not in selections and ref not in (
                        "selection", "filter"):
                    # Unknown bare word that is not a known keyword: only
                    # flag it when it looks like a selection reference
                    # (selection* or filter* prefixes are Sigma idiom).
                    if ref.startswith(("selection", "filter")):
                        errors.append(
                            f"condition references unknown selection: {ref}")
    elif detection is not None:
        errors.append("detection must be a mapping")

    if "tags" not in rule or not rule.get("tags"):
        warnings.append("rule has no tags")
    else:
        for tid in _tag_technique_ids(rule):
            if tid not in TECHNIQUES:
                errors.append(f"tag references unknown technique: {tid}")

    valid = not errors
    return {
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
        "blocked": bool(strict and not valid),
    }


def validate_rules(rules: list[dict], strict: bool = False) -> dict:
    """Validate many rules. Returns per-rule results plus a summary."""
    results = [validate_rule(r, strict=strict) for r in rules]
    return {
        "results": results,
        "summary": {
            "total": len(rules),
            "valid": sum(1 for r in results if r["valid"]),
            "blocked": sum(1 for r in results if r["blocked"]),
        },
    }
