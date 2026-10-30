"""Cycle 3 tests — defensive layer (authoritative tagging, coverage matrix,
gap register, Sigma export/gate, defensive MCP tools).

Plain no-deps runner, mirroring tests/test_regression.py: run with
``python tests/test_cycle3.py`` from the project root. The base suite in
tests/test_regression.py is NOT modified by this file.
"""
import ast
import json
import os
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import SESSION  # noqa: E402
from modules.mitre_data import TECHNIQUES, TACTICS  # noqa: E402
from modules.detection_data import DETECTION_DATA  # noqa: E402
from modules.technique_map import MODULE_TECHNIQUES  # noqa: E402
from modules.coverage import build_coverage_matrix  # noqa: E402
from modules.gap_register import (  # noqa: E402
    new_register, attest, import_observations, compute_gaps)
from modules.sigma_validate import validate_rule  # noqa: E402
from modules.sigma_export import export_rules  # noqa: E402
from modules.reporting import (  # noqa: E402
    _enrich_all, _build_html, _build_markdown, _build_json, _build_navigator)
from utils.helpers import add_finding  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The only two call sites deliberately left untagged (see BUILD_REPORT):
# forcing an ID on either would be fabrication.
UNTAGGED_EXCEPTIONS = {
    "AD Deception Validation Planned",
    "ADCS Scan Complete",
}


def _reset_session_findings():
    saved = SESSION.get("findings", [])
    SESSION["findings"] = []
    return saved


# ── 1. Tagging parameter + session persistence ─────────────────────────────

def test_tagging_param_stores_ids():
    saved = _reset_session_findings()
    try:
        f = add_finding("T1", "High", "d1", "r1",
                        technique_ids=["T1558.003", " T1558.003 ", "T1003.001"])
        assert f["technique_ids"] == ["T1558.003", "T1003.001"], f["technique_ids"]
        assert f["mitre_ids"] == ["T1558.003", "T1003.001"], f["mitre_ids"]
        g = add_finding("T2", "Low", "d2", "r2")
        assert g["technique_ids"] == [] and g["mitre_ids"] == []
    finally:
        SESSION["findings"] = saved


def test_tagging_dedup_merge_fills():
    saved = _reset_session_findings()
    try:
        add_finding("Dup", "High", "d", "r")
        assert SESSION["findings"][0]["technique_ids"] == []
        merged = add_finding("Dup", "High", "d", "r",
                             technique_ids=["T1078.002"])
        assert merged["technique_ids"] == ["T1078.002"]
        assert merged["mitre_ids"] == ["T1078.002"]
        assert len(SESSION["findings"]) == 1
    finally:
        SESSION["findings"] = saved


def test_session_persistence_after_enrichment():
    saved = _reset_session_findings()
    try:
        tagged = {"id": 1, "name": "Kerberoasting Successful",
                  "severity": "High", "description": "x", "recommendation": "y",
                  "technique_ids": ["T1558.003"], "mitre_ids": ["T1558.003"]}
        untagged = {"id": 2, "name": "Kerberoast-ish note",
                    "severity": "Low",
                    "description": "kerberoast ticket seen",
                    "recommendation": "y", "technique_ids": [],
                    "mitre_ids": []}
        enriched = _enrich_all([tagged, untagged])
        # Authoritative IDs survive enrichment untouched.
        assert enriched[0]["mitre_ids"] == ["T1558.003"]
        # Untagged findings still get the keyword-inference fallback.
        assert enriched[1]["mitre_ids"] == ["T1558.003"]
        # Persisting enriched findings (what reporting.run() does) makes the
        # IDs visible to every session consumer.
        SESSION["findings"] = enriched
        assert SESSION["findings"][0]["mitre_ids"] == ["T1558.003"]
        assert SESSION["findings"][1]["mitre_ids"] == ["T1558.003"]
    finally:
        SESSION["findings"] = saved


# ── 2. Backfill completeness (static, AST) ─────────────────────────────────

def _add_finding_calls():
    """Yield (module_key, name_literal, technique_ids_literal|None)."""
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "modules")):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, os.path.join(ROOT, "modules"))
            if rel == os.path.join("agent", "_core.py"):
                key = "agent._core"
            else:
                key = os.path.splitext(os.path.basename(path))[0]
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "add_finding"):
                    continue
                name = None
                if node.args and isinstance(node.args[0], ast.Constant):
                    name = node.args[0].value
                tids = None
                for kw in node.keywords:
                    if kw.arg == "technique_ids":
                        if isinstance(kw.value, ast.List):
                            tids = [e.value for e in kw.value.elts
                                    if isinstance(e, ast.Constant)]
                        else:
                            tids = "<non-literal>"
                yield key, name, tids


def test_backfill_every_callsite_tagged():
    untagged = []
    total = 0
    for key, name, tids in _add_finding_calls():
        total += 1
        if tids is None:
            untagged.append((key, name))
        elif tids == "<non-literal>":
            raise AssertionError(f"{key}: non-literal technique_ids")
        else:
            for tid in tids:
                assert tid in TECHNIQUES, f"{key}: unknown technique {tid}"
    assert total > 200, f"unexpectedly few call sites: {total}"
    assert len(untagged) == len(UNTAGGED_EXCEPTIONS), untagged
    assert {n for _, n in untagged} == UNTAGGED_EXCEPTIONS, untagged


def test_backfill_module_map_matches():
    unions: dict[str, set] = {}
    for key, _name, tids in _add_finding_calls():
        if tids:
            unions.setdefault(key, set()).update(tids)
    for key, ids in unions.items():
        assert key in MODULE_TECHNIQUES, f"map missing module {key}"
        assert set(MODULE_TECHNIQUES[key]) == ids, \
            f"map drift for {key}: {sorted(set(MODULE_TECHNIQUES[key]) ^ ids)}"
    # All 52 menu modules from main.py PHASES plus the agent core.
    # (PHASES embeds color constants, so literal_eval cannot be used;
    # walk the AST tuples instead.)
    with open(os.path.join(ROOT, "main.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    stems = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(
                node.targets[0], "id", "") == "PHASES":
            for phase in node.value.elts:
                items = phase.elts[3]
                for item in items.elts:
                    mod = item.elts[2].value
                    assert mod.startswith("modules.")
                    stems.add(mod[len("modules."):])
    assert len(stems) == 52, f"menu modules: {len(stems)}"
    assert set(MODULE_TECHNIQUES) == stems | {"agent._core"}, \
        f"map keys drift: {sorted(set(MODULE_TECHNIQUES) ^ (stems | {'agent._core'}))}"


# ── 3. Detection-data validity ─────────────────────────────────────────────

def test_detection_data_covers_registry():
    assert set(DETECTION_DATA) == set(TECHNIQUES), \
        f"missing: {sorted(set(TECHNIQUES) - set(DETECTION_DATA))}"
    for tid, entry in DETECTION_DATA.items():
        for field in ("log_sources", "channels", "windows_event_ids",
                      "sysmon_event_ids", "other_event_ids", "edr_notes",
                      "sigma_stub"):
            assert field in entry, f"{tid}: missing {field}"
        assert entry["log_sources"], f"{tid}: no log sources"
        for eid in entry["windows_event_ids"] + entry["sysmon_event_ids"]:
            assert isinstance(eid, int) and 1 <= eid <= 65535, \
                f"{tid}: malformed event id {eid!r}"
        for other in entry["other_event_ids"]:
            assert set(other) == {"channel", "ids"}
            assert all(isinstance(i, int) for i in other["ids"])
        stub = entry["sigma_stub"]
        for field in ("title", "id", "status", "description", "logsource",
                      "detection", "level", "tags"):
            assert field in stub, f"{tid}: stub missing {field}"
        uuid.UUID(stub["id"])  # raises unless a valid UUID
        assert stub["detection"]["condition"] == "selection"
        tag_tids = [t[len("attack."):].upper() for t in stub["tags"]
                    if t.startswith("attack.t")]
        assert tag_tids, f"{tid}: stub has no technique tag"
        for tt in tag_tids:
            assert tt in TECHNIQUES, f"{tid}: stub tags unknown {tt}"


def test_detection_data_empty_ids_are_deliberate():
    # Cloud token theft has no Windows/Sysmon footprint to honestly claim:
    # empty ID lists with real cloud log sources, not invented IDs.
    token_theft = DETECTION_DATA["T1528"]
    assert token_theft["windows_event_ids"] == []
    assert token_theft["sysmon_event_ids"] == []
    assert token_theft["log_sources"]


# ── 4. Coverage-matrix math ────────────────────────────────────────────────

def _seed_findings():
    return [
        {"id": 1, "name": "Kerberoasting Successful", "severity": "High",
         "description": "x", "recommendation": "y",
         "technique_ids": ["T1558.003"], "mitre_ids": ["T1558.003"]},
        {"id": 2, "name": "Kerberoast-ish note", "severity": "Low",
         "description": "kerberoast ticket seen", "recommendation": "y",
         "technique_ids": [], "mitre_ids": []},
        {"id": 3, "name": "Unrelated note", "severity": "Info",
         "description": "nothing mappable here", "recommendation": "y",
         "technique_ids": [], "mitre_ids": []},
    ]


def test_coverage_matrix_math():
    enriched = _enrich_all(_seed_findings())
    matrix = build_coverage_matrix(enriched)
    s = matrix["summary"]
    assert s["techniques_total"] == 58
    assert s["techniques_covered"] == 1, s
    assert s["tactics_covered"] == 1
    assert s["findings_authoritative"] == 1
    assert s["findings_inferred"] == 1
    assert s["findings_untagged"] == 1
    assert matrix["per_technique"]["T1558.003"]["status"] == "covered"
    assert matrix["per_technique"]["T1003.001"]["status"] == "uncovered"
    assert matrix["per_tactic"]["credential-access"]["covered"] is True
    assert matrix["per_tactic"]["reconnaissance"]["covered"] is False
    assert matrix["per_tactic"]["credential-access"]["techniques_covered"] == 1


def test_coverage_binary_only():
    matrix = build_coverage_matrix(_enrich_all(_seed_findings()))
    statuses = {e["status"] for e in matrix["per_technique"].values()}
    assert statuses <= {"covered", "uncovered"}, statuses
    for entry in matrix["per_technique"].values():
        assert "confidence" not in entry and "score" not in entry


# ── 5. MCP registry ────────────────────────────────────────────────────────

def test_mcp_registry_equal():
    import modules.agent._core as core
    tool_names = {t["name"] for t in core.TOOLS}
    map_names = set(core.TOOL_MAP)
    assert tool_names == map_names, \
        f"TOOLS-MAP drift: only-TOOLS={sorted(tool_names - map_names)} " \
        f"only-MAP={sorted(map_names - tool_names)}"
    for new in ("detection_coverage", "sigma_export", "gap_register_query"):
        assert new in tool_names and new in map_names, new
    for name, fn in core.TOOL_MAP.items():
        assert callable(fn), f"{name} not callable"


def test_mcp_tools_functional():
    import modules.agent._core as core
    saved = _reset_session_findings()
    try:
        SESSION["findings"] = [
            {"id": 1, "name": "Kerberoasting Successful", "severity": "High",
             "description": "x", "recommendation": "y",
             "technique_ids": ["T1558.003"], "mitre_ids": ["T1558.003"]},
        ]
        cov = json.loads(core.tool_detection_coverage())
        assert cov["summary"]["techniques_covered"] == 1
        one = json.loads(core.tool_detection_coverage(technique_id="T1558.003"))
        assert one["status"] == "covered"
        assert "error" in json.loads(core.tool_detection_coverage(
            technique_id="T9999"))
        with tempfile.TemporaryDirectory() as tmp:
            exp = json.loads(core.tool_sigma_export(output_dir=tmp))
            assert len(exp["written"]) == 1 and exp["blocked"] == []
            assert os.path.exists(exp["written"][0])
        gaps = json.loads(core.tool_gap_register_query(
            register_path=os.path.join(tempfile.gettempdir(),
                                       "c3_no_such_register.json")))
        assert gaps["summary"]["untested"] == 1
        assert gaps["summary"]["gaps"] == 0
    finally:
        SESSION["findings"] = saved


# ── 6. Sigma gate + export ─────────────────────────────────────────────────

def test_sigma_gate_valid_warns_blocks():
    stub = DETECTION_DATA["T1558.003"]["sigma_stub"]
    ok = validate_rule(stub)
    assert ok["valid"] and not ok["blocked"] and not ok["errors"]
    broken = dict(stub)
    broken["detection"] = {"selection": {"EventID": 4769},
                           "condition": "selection and selection_missing"}
    warn_mode = validate_rule(broken)
    assert not warn_mode["valid"] and not warn_mode["blocked"]
    assert any("selection_missing" in e for e in warn_mode["errors"])
    strict = validate_rule(broken, strict=True)
    assert strict["blocked"] is True
    unknown_source = dict(stub)
    unknown_source["logsource"] = {"product": "made_up_product"}
    res = validate_rule(unknown_source)
    assert res["valid"] and res["warnings"], res
    bad_tag = dict(stub)
    bad_tag["tags"] = ["attack.credential-access", "attack.t9999"]
    res = validate_rule(bad_tag)
    assert not res["valid"] and any("T9999" in e for e in res["errors"])


def test_sigma_export_writes_and_strict_blocks():
    import modules.sigma_export as sexp
    with tempfile.TemporaryDirectory() as tmp:
        res = export_rules(["T1558.003"], tmp)
        assert len(res["written"]) == 1
        assert os.path.exists(res["written"][0])
        with open(res["written"][0], encoding="utf-8") as fh:
            assert "T1558.003" in fh.read()
        broken = dict(DETECTION_DATA["T1558.003"]["sigma_stub"])
        broken["detection"] = {"selection": {"EventID": 4769},
                               "condition": "selection_missing"}
        orig = sexp.sigma_stub_for
        try:
            sexp.sigma_stub_for = lambda tid: broken  # noqa: E731
            res = export_rules(["T1558.003"], tmp, strict=True)
            assert res["blocked"] == ["T1558.003"] and res["written"] == []
        finally:
            sexp.sigma_stub_for = orig


# ── 7. Gap register ────────────────────────────────────────────────────────

def test_gap_register_import_attest_compute():
    findings = _enrich_all([_seed_findings()[0]])
    reg = new_register()
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as fh:
        json.dump([{"finding": "Kerberoasting Successful",
                    "technique_id": "T1558.003", "observed": True,
                    "note": "saw 4769 spike"}], fh)
        path = fh.name
    try:
        out = import_observations(reg, path)
        assert out["imported"] == 1
        gaps = compute_gaps(findings, reg)
        assert gaps["summary"] == {"expected_total": 1, "observed": 1,
                                   "gaps": 0, "untested": 0}, gaps["summary"]
        # Latest observation wins: a later "not seen" turns it into a gap.
        attest(reg, "Kerberoasting Successful", "T1558.003", False,
               "rechecked: no alert")
        gaps = compute_gaps(findings, reg)
        assert gaps["summary"]["gaps"] == 1
        assert gaps["rows"][0]["status"] == "gap"
        # Unobserved pairs stay untested, never gaps.
        gaps = compute_gaps(findings, new_register())
        assert gaps["rows"][0]["status"] == "untested"
    finally:
        os.unlink(path)
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as fh:
        json.dump([{"finding": "X", "technique_id": "T1558.003"}], fh)
        bad = fh.name
    try:
        with _raises(ValueError):
            import_observations(new_register(), bad)
    finally:
        os.unlink(bad)


class _raises:
    def __init__(self, exc):
        self.exc = exc

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, self.exc)


# ── 8. Reporting builders carry coverage + gaps ────────────────────────────

def test_reporting_builders_carry_coverage_and_gaps():
    findings = _enrich_all(_seed_findings())
    reg = new_register()
    attest(reg, "Kerberoasting Successful", "T1558.003", True, "saw it")
    html = _build_html("Demo", "T", "d.local", "10.0.0.1",
                       findings, [], [], [], {}, reg)
    assert "Detection Coverage Matrix" in html
    assert "Gap Register" in html
    md = _build_markdown("Demo", "T", "d.local", "10.0.0.1",
                         findings, [], [], {}, 0, reg)
    assert "## Detection Coverage Matrix" in md
    assert "## Gap Register" in md
    assert md.index("## Detection Coverage Matrix") < \
        md.index("## Gap Register") < md.index("## Findings")
    js = _build_json("Demo", "T", "d.local", "10.0.0.1",
                     findings, [], [], {}, [], reg)
    assert js["coverage"]["summary"]["techniques_covered"] == 1
    assert js["gap_register"]["summary"]["observed"] == 1
    nav = _build_navigator("Demo", findings, reg)
    names = {m["name"] for m in nav["metadata"]}
    assert {"coverage_techniques", "coverage_tactics",
            "gap_register"} <= names
    assert "Coverage: 1/58 techniques" in nav["description"]


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
