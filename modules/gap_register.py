"""
modules/gap_register.py — cycle 3 defensive layer (bounded purple-team loop).

The gap register pairs EXPECTED detections (derived from a finding's
authoritative technique IDs via modules/detection_data.py) with OBSERVED
input that comes from exactly two sources:

  1. JSON file import — a SIEM/export dump the operator hands us, with a
     strict schema (see OBSERVATION_SCHEMA below).
  2. Manual operator attestation — attest() records a human "we saw it /
     we did not see it" for one finding + technique pair.

There is NO SIEM connector, NO live ingestion, and NO promise of a closed
loop. An expected detection with no observation is "untested", not a gap:
only an explicit observed=False is a "gap". That distinction is the whole
point — the register must never claim a miss it never measured.

Observation schema (JSON file, top level is a list):
  [{"finding": <finding name or numeric id>,
    "technique_id": "T1558.003",
    "observed": true | false,
    "note": "free text (optional)",
    "timestamp": "ISO string (optional)"}]

Register storage: a plain JSON dict {"observations": [...]} kept in memory
and persisted with save_register()/load_register(). Reports read it; they
never write it.
"""
from __future__ import annotations

import json
import os

from modules.detection_data import expected_detections_for_finding


def new_register() -> dict:
    """Return an empty gap register."""
    return {"observations": []}


def _finding_ref(finding: dict) -> str:
    """Stable reference for a finding: numeric id when present, else name."""
    if finding.get("id") is not None:
        return str(finding["id"])
    return str(finding.get("name", ""))


def _matches(obs: dict, finding: dict) -> bool:
    """True when an observation refers to this finding (by id or name)."""
    ref = str(obs.get("finding", ""))
    if ref == _finding_ref(finding):
        return True
    return ref == str(finding.get("name", ""))


def attest(register: dict, finding_ref: str, technique_id: str,
           observed: bool, note: str = "") -> dict:
    """Record one manual operator attestation. Returns the observation."""
    obs = {
        "finding": str(finding_ref),
        "technique_id": technique_id,
        "observed": bool(observed),
        "note": note,
        "timestamp": "",
        "source": "attestation",
    }
    register.setdefault("observations", []).append(obs)
    return obs


def import_observations(register: dict, path: str) -> dict:
    """Import observations from a JSON file. Returns a summary.

    Raises ValueError on schema violations (wrong top-level type, missing
    finding/technique_id/observed, non-boolean observed). Nothing is
    partially imported: validation runs over the whole file first.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("observation file must contain a JSON list")
    cleaned = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"observation {i} is not an object")
        if "finding" not in item or "technique_id" not in item \
                or "observed" not in item:
            raise ValueError(
                f"observation {i} needs finding, technique_id, observed")
        if not isinstance(item["observed"], bool):
            raise ValueError(f"observation {i}: observed must be true/false")
        cleaned.append({
            "finding": str(item["finding"]),
            "technique_id": str(item["technique_id"]),
            "observed": item["observed"],
            "note": str(item.get("note", "")),
            "timestamp": str(item.get("timestamp", "")),
            "source": "import",
        })
    register.setdefault("observations", []).extend(cleaned)
    return {"imported": len(cleaned), "path": path}


def load_register(path: str) -> dict:
    """Load a register from disk; empty register when the file is absent."""
    if not path or not os.path.exists(path):
        return new_register()
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "observations" not in data:
        raise ValueError("register file must contain {\"observations\": [...]}")
    return data


def save_register(register: dict, path: str) -> str:
    """Persist a register to disk (creates parent dirs). Returns path."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(register, fh, indent=2)
    return path


def compute_gaps(findings: list[dict], register: dict | None) -> dict:
    """Compute gap rows for findings against a register.

    Each row is one (finding, technique) pair with its expected detection
    telemetry and a status:
      observed  — an observation says the detection fired.
      gap       — an observation says it did NOT fire.
      untested  — no observation recorded for this pair.
    When several observations exist for one pair, the latest wins.
    """
    observations = (register or {}).get("observations", [])
    rows = []
    for f in findings:
        for exp in expected_detections_for_finding(f):
            tid = exp["technique_id"]
            latest = None
            for obs in observations:
                if obs.get("technique_id") == tid and _matches(obs, f):
                    latest = obs
            if latest is None:
                status, note = "untested", ""
            elif latest.get("observed"):
                status, note = "observed", str(latest.get("note", ""))
            else:
                status, note = "gap", str(latest.get("note", ""))
            rows.append({
                "finding": str(f.get("name", "")),
                "finding_id": f.get("id"),
                "technique_id": tid,
                "technique_name": exp["technique_name"],
                "tactic": exp["tactic"],
                "expected_log_sources": exp["log_sources"],
                "expected_channels": exp["channels"],
                "expected_windows_event_ids": exp["windows_event_ids"],
                "expected_sysmon_event_ids": exp["sysmon_event_ids"],
                "status": status,
                "note": note,
            })
    n_gap = sum(1 for r in rows if r["status"] == "gap")
    n_obs = sum(1 for r in rows if r["status"] == "observed")
    n_unt = sum(1 for r in rows if r["status"] == "untested")
    return {
        "rows": rows,
        "summary": {
            "expected_total": len(rows),
            "observed": n_obs,
            "gaps": n_gap,
            "untested": n_unt,
        },
    }
