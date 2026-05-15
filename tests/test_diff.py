""" Tests for backend.reports.compute_diff and create_diff_report """

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

from backend import reports
from backend.reports import compute_diff, create_diff_report

from tests.test_reports import _fake_dt_get


def _component(name, version, vulns, group=""):
    return {
        "name": name,
        "version": version,
        "group": group,
        "vulnerabilities": vulns,
    }


def _vuln(vuln_id, severity="high", state="", suppressed=False):
    return {
        "id": vuln_id,
        "link": f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
        "severity": severity,
        "priority": severity,
        "analysis_state": state,
        "is_suppressed": suppressed,
    }


def _data(*components):
    return {"vuln_components": list(components)}


def test_compute_diff_empty_on_both_sides():
    result = compute_diff(_data(), _data())
    assert result == {"added": [], "removed": [], "common": []}


def test_compute_diff_finds_added_vuln():
    a = _data()
    b = _data(_component("libA", "1.0", [_vuln("CVE-2024-0001")]))
    result = compute_diff(a, b)
    assert len(result["added"]) == 1
    assert result["added"][0]["component"] == "libA"
    assert result["added"][0]["vulnerability"] == "CVE-2024-0001"
    assert result["added"][0]["componentVersion"] == "1.0"
    assert result["removed"] == []
    assert result["common"] == []


def test_compute_diff_finds_removed_vuln():
    a = _data(_component("libA", "1.0", [_vuln("CVE-2024-0001")]))
    b = _data()
    result = compute_diff(a, b)
    assert len(result["removed"]) == 1
    assert result["removed"][0]["vulnerability"] == "CVE-2024-0001"
    assert result["added"] == []


def test_compute_diff_finds_common_with_version_change():
    """ Same CVE in both projects but the host component was bumped """
    a = _data(_component("libA", "1.0", [_vuln("CVE-2024-0001")]))
    b = _data(_component("libA", "1.5", [_vuln("CVE-2024-0001")]))
    result = compute_diff(a, b)
    assert len(result["common"]) == 1
    common = result["common"][0]
    assert common["componentVersionA"] == "1.0"
    assert common["componentVersionB"] == "1.5"
    assert common["versionChanged"] is True
    assert common["vulnerability"] == "CVE-2024-0001"
    assert result["added"] == []
    assert result["removed"] == []


def test_compute_diff_common_version_unchanged_flag():
    """ Same CVE on same version in both projects -> versionChanged is False """
    a = _data(_component("libA", "1.0", [_vuln("CVE-2024-0001")]))
    b = _data(_component("libA", "1.0", [_vuln("CVE-2024-0001")]))
    result = compute_diff(a, b)
    assert len(result["common"]) == 1
    assert result["common"][0]["versionChanged"] is False


def test_compute_diff_distinguishes_groups():
    """ Same component name in different groups are different identities """
    a = _data(_component("util", "1.0", [_vuln("CVE-X")], group="org.foo"))
    b = _data(_component("util", "1.0", [_vuln("CVE-X")], group="org.bar"))
    result = compute_diff(a, b)
    assert len(result["added"]) == 1
    assert len(result["removed"]) == 1
    assert result["common"] == []


def test_compute_diff_mixed_added_removed_common():
    a = _data(
        _component("libA", "1.0", [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")]),
        _component("libB", "2.0", [_vuln("CVE-2024-0003")]),
    )
    b = _data(
        _component("libA", "1.1", [_vuln("CVE-2024-0001")]),  # 0002 fixed
        _component("libC", "3.0", [_vuln("CVE-2024-0009")]),  # new component
    )
    result = compute_diff(a, b)
    added_ids = sorted(e["vulnerability"] for e in result["added"])
    removed_ids = sorted(e["vulnerability"] for e in result["removed"])
    common_ids = sorted(e["vulnerability"] for e in result["common"])
    assert added_ids == ["CVE-2024-0009"]
    assert removed_ids == ["CVE-2024-0002", "CVE-2024-0003"]
    assert common_ids == ["CVE-2024-0001"]


def test_compute_diff_carries_analysis_state_per_side():
    """ Common vulns may have different VEX state in A vs B """
    a = _data(_component("libA", "1.0",
                         [_vuln("CVE-X", state="exploitable", suppressed=False)]))
    b = _data(_component("libA", "1.0",
                         [_vuln("CVE-X", state="false_positive", suppressed=True)]))
    result = compute_diff(a, b)
    assert len(result["common"]) == 1
    c = result["common"][0]
    assert c["analysisStateA"] == "exploitable"
    assert c["analysisStateB"] == "false_positive"
    assert c["isSuppressedA"] is False
    assert c["isSuppressedB"] is True


# create_diff_report integration

def _payloads_for(version, vuln_ids, last_bom_ms=0):
    """ Mock fixture: a project at <version> with the given vulns on libA """
    return [
        (lambda u: u.endswith("/project"), []),
        ("finding/project", []),
        ("bom/cyclonedx", {
            "vulnerabilities": [
                {"bom-ref": v, "id": v, "ratings": [{"severity": "high"}],
                 "affects": [{"ref": "c1"}]}
                for v in vuln_ids
            ],
            "dependencies": [{"ref": "c1", "dependsOn": []}],
        }),
        ("component/project", [
            {"uuid": "c1", "name": "libA", "version": version, "group": "",
             "repositoryMeta": None},
        ]),
        ("/project/", {"name": "demo", "version": version, "metrics": {},
                       "directDependencies": "[]",
                       "lastBomImport": last_bom_ms}),
    ]


def _config(project_uuid):
    return {
        "url": ["https://example.com"],
        "token": ["t"],
        "project": [project_uuid],
    }


def test_create_diff_report_writes_xlsx_and_summary(monkeypatch):
    monkeypatch.delenv("DTRG_INCLUDE_SUPPRESSED", raising=False)
    # First call (project A) gets one payload set; second call (project B) the other.
    fixture_a = _fake_dt_get(_payloads_for("1.0", ["CVE-2024-0001",
                                                   "CVE-2024-0002"],
                                            last_bom_ms=1_000))
    fixture_b = _fake_dt_get(_payloads_for("1.1", ["CVE-2024-0001"],
                                            last_bom_ms=2_000))
    call_state = {"is_b": False, "switch_after": 4}  # 4 calls for project A
    counter = {"n": 0}

    def dispatch(url, headers=None, verify=None, timeout=None):
        counter["n"] += 1
        if counter["n"] <= call_state["switch_after"]:
            return fixture_a(url, headers=headers, verify=verify, timeout=timeout)
        return fixture_b(url, headers=headers, verify=verify, timeout=timeout)

    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get", side_effect=dispatch):
        report, components = create_diff_report(
            _config("00000000-0000-0000-0000-000000000001"),
            _config("00000000-0000-0000-0000-000000000002"),
            td)
        assert isinstance(report, str)
        assert components is None
        assert os.path.exists(os.path.join(td, "result.xlsx"))
        with open(os.path.join(td, "summary.json"), encoding="utf-8") as f:
            summary = json.load(f)

    assert summary["kind"] == "diff"
    assert summary["projectA"]["version"] == "1.0"
    assert summary["projectB"]["version"] == "1.1"
    added_ids = sorted(e["vulnerability"] for e in summary["diff"]["added"])
    removed_ids = sorted(e["vulnerability"] for e in summary["diff"]["removed"])
    common_ids = sorted(e["vulnerability"] for e in summary["diff"]["common"])
    assert added_ids == []  # B has no new CVEs vs A
    assert removed_ids == ["CVE-2024-0002"]  # this one was fixed
    assert common_ids == ["CVE-2024-0001"]  # this one stayed


def test_create_diff_report_dedups_cve_paas_into_single_batch(monkeypatch):
    """ Diff fetches CVE-PaaS once for the union of A's and B's CVE ids """
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    monkeypatch.delenv("DTRG_INCLUDE_SUPPRESSED", raising=False)
    fa = _fake_dt_get(_payloads_for("1.0", ["CVE-2024-0001"],
                                     last_bom_ms=1_000))
    fb = _fake_dt_get(_payloads_for("1.1", ["CVE-2024-0001"],
                                     last_bom_ms=2_000))
    counter = {"get": 0}

    def dispatch(url, headers=None, verify=None, timeout=None):
        counter["get"] += 1
        if counter["get"] == 1 or 3 <= counter["get"] <= 6:
            return fa(url)
        return fb(url)

    post_calls = []
    def fake_post(url, json=None, headers=None, verify=None, timeout=None):
        post_calls.append(json)
        res = MagicMock()
        res.status_code = 200
        res.raise_for_status = lambda: None
        res.json = lambda: {}
        return res

    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get", side_effect=dispatch), \
         patch.object(reports.requests, "post", side_effect=fake_post):
        reports.create_diff_report(
            _config("00000000-0000-0000-0000-00000000000a"),
            _config("00000000-0000-0000-0000-00000000000b"),
            td)
    # Exactly one CVE-PaaS request, carrying the union (one CVE in this fixture)
    assert len(post_calls) == 1
    assert post_calls[0]["cve_ids"] == ["CVE-2024-0001"]


def test_create_diff_report_swaps_so_newer_is_b(monkeypatch):
    """ Operator passes newer-then-older; dtrg swaps so B is the newer one """
    monkeypatch.delenv("DTRG_INCLUDE_SUPPRESSED", raising=False)
    # First call (in argument order = "A") is the NEWER project.
    # Second call ("B") is the OLDER. dtrg should swap them so the diff
    # answers "what changed going from old to new", not the reverse.
    fixture_a_newer = _fake_dt_get(_payloads_for(
        "1.1", ["CVE-2024-0001"], last_bom_ms=2_000))
    fixture_b_older = _fake_dt_get(_payloads_for(
        "1.0", ["CVE-2024-0001", "CVE-2024-0002"], last_bom_ms=1_000))
    counter = {"n": 0}

    def dispatch(url, headers=None, verify=None, timeout=None):
        counter["n"] += 1
        if counter["n"] <= 4:
            return fixture_a_newer(url, headers=headers, verify=verify, timeout=timeout)
        return fixture_b_older(url, headers=headers, verify=verify, timeout=timeout)

    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get", side_effect=dispatch):
        create_diff_report(
            _config("00000000-0000-0000-0000-00000000000a"),
            _config("00000000-0000-0000-0000-00000000000b"),
            td)
        with open(os.path.join(td, "summary.json"), encoding="utf-8") as f:
            summary = json.load(f)
    # After swap: B (the report says "newer") must be 1.1.
    assert summary["projectB"]["version"] == "1.1"
    assert summary["projectA"]["version"] == "1.0"
    # And the diff partitioning must reflect old->new direction.
    removed_ids = sorted(e["vulnerability"] for e in summary["diff"]["removed"])
    common_ids = sorted(e["vulnerability"] for e in summary["diff"]["common"])
    assert removed_ids == ["CVE-2024-0002"]  # fixed in newer
    assert common_ids == ["CVE-2024-0001"]
