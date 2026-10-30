"""
modules/coverage.py — cycle 3 defensive layer.

Binary detection-coverage matrix over the MITRE registry, computed from
enriched findings. Deliberately binary: a technique is "covered" when at
least one finding carries it AND detection data exists for it; otherwise
"uncovered". No confidence scores — a scored estimate built on a
hand-authored mapping would be false precision (see AUDIT §5, idea (a)
deferred).

Tagging provenance is preserved separately: a finding counts as
"authoritative" when it carries technique_ids recorded at source, and
"inferred" when its mitre_ids came only from report-time keyword
inference (technique_ids empty). That split is what proves the tagging
layer changed anything.
"""
from __future__ import annotations

from modules.mitre_data import TACTICS, TECHNIQUES
from modules.detection_data import DETECTION_DATA


def build_coverage_matrix(findings: list[dict]) -> dict:
    """Build the coverage matrix for a list of enriched findings.

    Returns:
      per_tactic:    tactic -> {label, techniques_total, techniques_covered,
                     techniques_observed, findings, covered}
      per_technique: tid -> {name, tactic, status, observed, findings,
                     detection_available, log_sources}
      summary:       totals + tagging provenance counts
    """
    observed: dict[str, list[str]] = {}   # tid -> finding names
    n_authoritative = n_inferred = n_untagged = 0
    for f in findings:
        mids = f.get("mitre_ids", []) or []
        if f.get("technique_ids"):
            n_authoritative += 1
        elif mids:
            n_inferred += 1
        else:
            n_untagged += 1
        for tid in mids:
            if tid in TECHNIQUES:
                observed.setdefault(tid, []).append(str(f.get("name", "")))

    per_technique: dict[str, dict] = {}
    for tid, tech in sorted(TECHNIQUES.items()):
        det = DETECTION_DATA.get(tid)
        is_observed = tid in observed
        covered = bool(is_observed and det)
        per_technique[tid] = {
            "name": tech.get("name", tid),
            "tactic": tech.get("tactic", ""),
            "status": "covered" if covered else "uncovered",
            "observed": is_observed,
            "detection_available": det is not None,
            "log_sources": list(det["log_sources"]) if det else [],
            "findings": observed.get(tid, []),
        }

    per_tactic: dict[str, dict] = {}
    for tac_id, label in TACTICS.items():
        tids = [t for t, d in TECHNIQUES.items() if d.get("tactic") == tac_id]
        cov = [t for t in tids if per_technique[t]["status"] == "covered"]
        per_tactic[tac_id] = {
            "label": label,
            "techniques_total": len(tids),
            "techniques_covered": len(cov),
            "techniques_observed": sorted(cov),
            "findings": sum(len(per_technique[t]["findings"]) for t in tids),
            "covered": bool(cov),
        }

    n_covered = sum(1 for t in per_technique.values()
                    if t["status"] == "covered")
    n_tactics = sum(1 for t in per_tactic.values() if t["covered"])
    return {
        "per_tactic": per_tactic,
        "per_technique": per_technique,
        "summary": {
            "techniques_total": len(TECHNIQUES),
            "techniques_covered": n_covered,
            "tactics_total": len(TACTICS),
            "tactics_covered": n_tactics,
            "findings_total": len(findings),
            "findings_authoritative": n_authoritative,
            "findings_inferred": n_inferred,
            "findings_untagged": n_untagged,
        },
    }
