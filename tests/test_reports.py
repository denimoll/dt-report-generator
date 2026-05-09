""" Tests for backend.reports """

import json
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from backend import reports


# get_severity

def test_get_severity_picks_max_known():
    level, label = reports.get_severity(["low", "high", "medium"])
    assert label == "high"
    assert level == 3

def test_get_severity_handles_case():
    level, label = reports.get_severity(["LOW", "Critical"])
    assert label == "critical"
    assert level == 4

def test_get_severity_treats_unknown_as_zero():
    level, label = reports.get_severity(["mystery", None, ""])
    assert level == 0
    # the function returns the first key whose value matches the level
    assert label in {"unknown", "undefined", "info"}

def test_get_severity_known_plus_unknown():
    level, label = reports.get_severity(["mystery", "high"])
    assert label == "high"
    assert level == 3


# VEX filtering through create_report (mocked DT API)

def _fake_dt_get(payloads):
    """ Build a side_effect that returns mock responses based on URL match.

    payloads is a list of (predicate, body); the first predicate that matches
    the request URL wins. predicate can be a substring or a callable.
    """
    def _matches(predicate, url):
        return predicate(url) if callable(predicate) else predicate in url

    def _get(url, headers=None, verify=None, timeout=None):
        m = MagicMock()
        m.status_code = 200
        m.raise_for_status = lambda: None
        body = next((b for pred, b in payloads if _matches(pred, url)), {})
        m.text = json.dumps(body)
        m.json = lambda b=body: b
        return m
    return _get


def _config():
    return {
        "url": ["https://example.com"],
        "token": ["t"],
        "project": ["00000000-0000-0000-0000-000000000000"],
    }


def _payloads_with_vex():
    return [
        # check_token probe — exact endswith /project (no trailing slash or uuid)
        (lambda u: u.endswith("/project"), []),
        # findings API: empty in this fixture, all analysis carried in SBOM
        ("finding/project", []),
        # SBOM with mixed analysis states
        ("bom/cyclonedx", {
            "vulnerabilities": [
                {"bom-ref": "v1", "id": "CVE-2024-0001",
                 "ratings": [{"severity": "high"}],
                 "affects": [{"ref": "c1"}],
                 "analysis": {"state": "exploitable"}},
                {"bom-ref": "v2", "id": "CVE-2024-0002",
                 "ratings": [{"severity": "critical"}],
                 "affects": [{"ref": "c2"}],
                 "analysis": {"state": "not_affected",
                              "justification": "code_not_present"}},
                {"bom-ref": "v3", "id": "CVE-2024-0003",
                 "ratings": [{"severity": "medium"}],
                 "affects": [{"ref": "c3"}]},
            ],
            "dependencies": [
                {"ref": "c1", "dependsOn": []},
                {"ref": "c2", "dependsOn": []},
                {"ref": "c3", "dependsOn": []},
            ],
        }),
        ("component/project", [
            {"uuid": "c1", "name": "libA", "version": "1", "group": "",
             "repositoryMeta": None},
            {"uuid": "c2", "name": "libB", "version": "2", "group": "",
             "repositoryMeta": None},
            {"uuid": "c3", "name": "libC", "version": "3", "group": "",
             "repositoryMeta": None},
        ]),
        # project metadata - matched last because the pattern is generic
        ("/project/", {"name": "demo", "version": "1.0", "metrics": {},
                       "directDependencies": "[]"}),
    ]


def _live_ids(components):
    return sorted(v["id"] for c in components.values() for v in c["vulnerabilities"])


def test_create_report_filters_suppressed_by_default(monkeypatch):
    monkeypatch.delenv("DTRG_INCLUDE_SUPPRESSED", raising=False)
    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get",
                      side_effect=_fake_dt_get(_payloads_with_vex())):
        report, components = reports.create_report(_config(), td)
    assert isinstance(report, str)
    assert _live_ids(components) == ["CVE-2024-0001", "CVE-2024-0003"]


def test_create_report_keeps_suppressed_when_env_set(monkeypatch):
    monkeypatch.setenv("DTRG_INCLUDE_SUPPRESSED", "true")
    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get",
                      side_effect=_fake_dt_get(_payloads_with_vex())):
        report, components = reports.create_report(_config(), td)
    assert _live_ids(components) == ["CVE-2024-0001", "CVE-2024-0002",
                                     "CVE-2024-0003"]
    suppressed = [v for c in components.values() for v in c["vulnerabilities"]
                  if v["is_suppressed"]]
    assert len(suppressed) == 1
    assert suppressed[0]["analysis_state"] == "not_affected"
    assert suppressed[0]["analysis_justification"] == "code_not_present"


def test_create_report_records_suppressed_count(monkeypatch):
    monkeypatch.delenv("DTRG_INCLUDE_SUPPRESSED", raising=False)
    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get",
                      side_effect=_fake_dt_get(_payloads_with_vex())):
        reports.create_report(_config(), td)
    # the fixture has exactly one not_affected finding
    # we look at the rendered docx's project_info indirectly via the suppressed_count log path
    # — easier: re-run with include=true and confirm the dropped one comes back
    monkeypatch.setenv("DTRG_INCLUDE_SUPPRESSED", "true")
    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get",
                      side_effect=_fake_dt_get(_payloads_with_vex())):
        _, components_full = reports.create_report(_config(), td)
    monkeypatch.delenv("DTRG_INCLUDE_SUPPRESSED", raising=False)
    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get",
                      side_effect=_fake_dt_get(_payloads_with_vex())):
        _, components_filtered = reports.create_report(_config(), td)
    full_total = sum(len(c["vulnerabilities"]) for c in components_full.values())
    filtered_total = sum(len(c["vulnerabilities"])
                         for c in components_filtered.values())
    assert full_total - filtered_total == 1


# project parsing

def test_create_report_accepts_bare_uuid(monkeypatch):
    """ API path passes a bare UUID, not "name version (uuid)" """
    monkeypatch.delenv("DTRG_INCLUDE_SUPPRESSED", raising=False)
    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get",
                      side_effect=_fake_dt_get(_payloads_with_vex())):
        report, _ = reports.create_report(_config(), td)
    assert isinstance(report, str)


def test_create_report_extracts_uuid_from_form_value(monkeypatch):
    """ Form path passes "name version (uuid)" """
    monkeypatch.delenv("DTRG_INCLUDE_SUPPRESSED", raising=False)
    cfg = {
        "url": ["https://example.com"],
        "token": ["t"],
        "project": ["demo 1.0 (00000000-0000-0000-0000-000000000000)"],
    }
    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get",
                      side_effect=_fake_dt_get(_payloads_with_vex())):
        report, _ = reports.create_report(cfg, td)
    assert isinstance(report, str)


def _payloads_findings_only():
    """ DT export without VEX in SBOM but a false-positive marked in the UI """
    return [
        (lambda u: u.endswith("/project"), []),
        ("finding/project", [
            {"vulnerability": {"vulnId": "CVE-2024-9999", "uuid": "v-uuid"},
             "component": {"uuid": "c1", "name": "libA"},
             "analysis": {"state": "FALSE_POSITIVE", "isSuppressed": True}},
        ]),
        ("bom/cyclonedx", {
            "vulnerabilities": [
                {"bom-ref": "v-uuid", "id": "CVE-2024-9999",
                 "ratings": [{"severity": "high"}],
                 "affects": [{"ref": "c1"}]},
            ],
            "dependencies": [{"ref": "c1", "dependsOn": []}],
        }),
        ("component/project", [
            {"uuid": "c1", "name": "libA", "version": "1", "group": "",
             "repositoryMeta": None},
        ]),
        ("/project/", {"name": "demo", "version": "1.0", "metrics": {},
                       "directDependencies": "[]"}),
    ]


def test_findings_api_supplies_analysis_when_sbom_omits_it(monkeypatch):
    """ The actual user-reported bug: a FP marked in DT must reach the report """
    monkeypatch.setenv("DTRG_INCLUDE_SUPPRESSED", "true")
    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get",
                      side_effect=_fake_dt_get(_payloads_findings_only())):
        report, components = reports.create_report(_config(), td)
    assert isinstance(report, str)
    vulns = [v for c in components.values() for v in c["vulnerabilities"]]
    assert len(vulns) == 1
    assert vulns[0]["analysis_state"] == "false_positive"
    assert vulns[0]["is_suppressed"] is True


def test_findings_api_filters_fp_by_default(monkeypatch):
    """ Same setup but default mode drops the FP from the report """
    monkeypatch.delenv("DTRG_INCLUDE_SUPPRESSED", raising=False)
    with tempfile.TemporaryDirectory() as td, \
         patch.object(reports.requests, "get",
                      side_effect=_fake_dt_get(_payloads_findings_only())):
        _, components = reports.create_report(_config(), td)
    vulns = [v for c in components.values() for v in c["vulnerabilities"]]
    assert vulns == []  # the only finding was a FP and it was filtered


def test_create_report_returns_value_error_on_missing_url():
    cfg = {"project": ["00000000-0000-0000-0000-000000000000"]}
    with tempfile.TemporaryDirectory() as td:
        report, components = reports.create_report(cfg, td)
    assert isinstance(report, ValueError)
    assert components == []
