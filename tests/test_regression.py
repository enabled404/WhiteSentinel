#!/usr/bin/env python3
"""
AdStrike regression tests.

Covers the agent fixes so they don't silently regress. Pure-logic only — no
network, no live target, no subprocess that needs a DC. Runs two ways:

    venv/bin/python -m pytest tests/            # if pytest installed
    venv/bin/python tests/test_regression.py    # plain runner, no deps

Run from the repo root.
"""
import os
import re
import sys

# Make the repo root importable when run directly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import SESSION
from utils.helpers import add_finding, PROOF_LEVELS
import modules.agent._core as core


# ── #2 Evidence-grade reporting (add_finding) ────────────────────────────────
def test_add_finding_default_proof_level():
    SESSION["findings"] = []
    f = add_finding("F1", "High", "d", "r")
    assert f["proof_level"] == "observed"
    assert f["command"] == ""
    assert f["timestamp"]


def test_add_finding_explicit_evidence_fields():
    SESSION["findings"] = []
    f = add_finding("F2", "Critical", "d", "r",
                    proof_level="exploited", command="certipy auth ...")
    assert f["proof_level"] == "exploited"
    assert "certipy" in f["command"]


def test_add_finding_invalid_proof_level_falls_back():
    SESSION["findings"] = []
    f = add_finding("F3", "Low", "d", "r", proof_level="totally-bogus")
    assert f["proof_level"] == "observed"


def test_add_finding_dedup_keeps_strongest_proof():
    SESSION["findings"] = []
    add_finding("Dup", "Critical", "d", "r", proof_level="observed")
    add_finding("Dup", "Critical", "d", "r", proof_level="owned")
    findings = [x for x in SESSION["findings"] if x["name"] == "Dup"]
    assert len(findings) == 1                      # deduped
    assert findings[0]["proof_level"] == "owned"   # upgraded


def test_proof_levels_ordered():
    assert PROOF_LEVELS.index("observed") < PROOF_LEVELS.index("exploited") < \
           PROOF_LEVELS.index("owned")


# ── ESC1 word-boundary guard (substring bug fix) ─────────────────────────────
def test_esc1_word_boundary_does_not_match_esc13():
    assert re.search(r"ESC1\b", "found ESC13 vulnerable") is None
    assert re.search(r"ESC1\b", "ESC10 ESC11 ESC16") is None
    assert re.search(r"ESC1\b", "template is ESC1 vulnerable") is not None


# ── Ollama evidence-based menu reasons ───────────────────────────────────────
def test_ollama_candidate_reason_known_tools():
    SESSION.clear()
    SESSION["agent_intel"] = {"spns": ["a", "b"], "gmsa_candidates": ["msa$"]}
    assert "SPN" in core._ollama_candidate_reason("kerberoast")
    assert "gMSA" in core._ollama_candidate_reason("gmsa_takeover")
    # unknown tool still returns a sensible default, never crashes
    assert core._ollama_candidate_reason("definitely_not_a_tool")


# ── SAST knowledge base loaded (path-fix: 0 -> 93) ───────────────────────────
def test_sast_knowledge_base_loaded():
    assert core._TOTAL_TECHNIQUES > 0, "SAST KB failed to load (path bug?)"
    assert len(core.SAST_SKILLS) >= 5


def test_sast_hint_exact_technique_mapping():
    hint = core._sast_hint_for_tool("kerberoast")
    assert "Kerberoast" in hint and "T1558" in hint
    # unmapped tool → category-level or empty, never a misleading specific
    core._sast_hint_for_tool("gmsa_takeover")  # must not raise


# ── Privileged ADCS ccache pointer (Option B verifier) ───────────────────────
def test_active_priv_ccache_empty_when_not_shell_ready():
    SESSION.clear()
    SESSION["agent_intel"] = {"adcs_shell_ready": False, "adcs_ccache": ""}
    assert core._active_priv_ccache("alice", "corp.local") == ""


# ── Neo4j preflight ──────────────────────────────────────────────────────────
def test_neo4j_unreachable_on_closed_port():
    # 127.0.0.1:1 is reserved/closed → fast False, no JVM noise.
    assert core._neo4j_reachable("bolt://127.0.0.1:1", timeout=1.0) is False


def test_strip_jvm_noise():
    raw = ("WARNING: sun.misc.Unsafe::objectFieldOffset has been called\n"
           "real result row\n"
           "WARNING: A restricted method in java.lang.System")
    out = core._strip_jvm_noise(raw)
    assert "WARNING" not in out
    assert "real result row" in out


# ── Self-target guard (shadow credentials must hit a victim, not the attacker) ─
def test_shadow_credentials_rejects_self_target():
    out = core.tool_shadow_credentials("attacker", "pw", "attacker",
                                       "10.0.0.1", "corp.local")
    assert "skipped" in out.lower()
    assert "attacking account" in out.lower()


def test_shadow_credentials_rejects_placeholder_target():
    out = core.tool_shadow_credentials("attacker", "pw", "found",
                                       "10.0.0.1", "corp.local")
    assert "skipped" in out.lower()


# ── Text tool-call parser (qwen/mistral markdown JSON) ───────────────────────
def test_parse_json_tool_call_markdown():
    content = '```json\n{"name": "nmap_scan", "arguments": {"target_ip": "10.0.0.1"}}\n```'
    parsed = core._parse_json_tool_call(content)
    assert parsed and parsed[0] == "nmap_scan"


# ── Plain runner (no pytest needed) ──────────────────────────────────────────
def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as exc:
            print(f"  FAIL  {t.__name__}: {exc}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed ({len(tests)} total)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
