""" Tests for the CVE-PaaS integration helpers in backend.reports """

from unittest.mock import MagicMock, patch

import pytest
import requests

from backend import reports
from backend.reports import _canonical_cve_ids, _fetch_cve_paas


# _canonical_cve_ids

def test_canonical_cve_ids_keeps_canonical_form():
    vulns = [
        {"id": "CVE-2024-0001"},
        {"id": "CVE-2024-12345"},
    ]
    assert _canonical_cve_ids(vulns) == {"CVE-2024-0001", "CVE-2024-12345"}


def test_canonical_cve_ids_drops_non_canonical():
    vulns = [
        {"id": "GHSA-xxxx-yyyy-zzzz"},
        {"id": "BIT-2024-9999"},
        {"id": ""},
        {"id": None},
        {},  # missing id
    ]
    assert _canonical_cve_ids(vulns) == set()


def test_canonical_cve_ids_dedups():
    vulns = [{"id": "CVE-2024-0001"}, {"id": "CVE-2024-0001"}]
    assert _canonical_cve_ids(vulns) == {"CVE-2024-0001"}


# _fetch_cve_paas

def test_fetch_cve_paas_returns_empty_without_env(monkeypatch):
    monkeypatch.delenv("CVEPAAS_URL", raising=False)
    assert _fetch_cve_paas({"CVE-2024-0001"}) == {}


def test_fetch_cve_paas_info_logs_when_url_unset(monkeypatch, caplog):
    """ Operators see a single info line per report when CVE-PaaS is off """
    monkeypatch.delenv("CVEPAAS_URL", raising=False)
    import logging
    with caplog.at_level(logging.INFO, logger="backend.reports"):
        _fetch_cve_paas({"CVE-2024-0001"})
    assert any("CVEPAAS_URL not set" in r.message for r in caplog.records)


def test_fetch_cve_paas_returns_empty_for_empty_input(monkeypatch):
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    assert _fetch_cve_paas(set()) == {}


def _post_response(payload):
    res = MagicMock()
    res.status_code = 200
    res.raise_for_status = lambda: None
    res.json = lambda: payload
    return res


def test_fetch_cve_paas_calls_v1_cve_with_payload(monkeypatch):
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    monkeypatch.delenv("DTRG_CVEPAAS_KEY", raising=False)
    payload = {"CVE-2024-0001": {"Priority": "High"}}
    with patch.object(reports.requests, "post",
                      return_value=_post_response(payload)) as mocked:
        result = _fetch_cve_paas({"CVE-2024-0001"})
    args, kwargs = mocked.call_args
    assert args[0] == "https://cvepaas.example.com/v1/cve"
    assert kwargs["json"] == {"cve_ids": ["CVE-2024-0001"]}
    assert kwargs["headers"] == {}
    assert result == payload


def test_fetch_cve_paas_attaches_api_key_when_env_set(monkeypatch):
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    monkeypatch.setenv("DTRG_CVEPAAS_KEY", "secret-key")
    with patch.object(reports.requests, "post",
                      return_value=_post_response({})) as mocked:
        _fetch_cve_paas({"CVE-2024-0001"})
    _, kwargs = mocked.call_args
    assert kwargs["headers"]["X-API-Key"] == "secret-key"


def test_fetch_cve_paas_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com/")
    with patch.object(reports.requests, "post",
                      return_value=_post_response({})) as mocked:
        _fetch_cve_paas({"CVE-2024-0001"})
    args, _ = mocked.call_args
    assert args[0] == "https://cvepaas.example.com/v1/cve"


def test_fetch_cve_paas_chunks_into_batches_of_50(monkeypatch):
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    cve_ids = {f"CVE-2024-{n:04d}" for n in range(120)}  # 120 ids
    with patch.object(reports.requests, "post",
                      return_value=_post_response({})) as mocked:
        _fetch_cve_paas(cve_ids)
    # 120 / 50 = 3 calls
    assert mocked.call_count == 3
    sizes = [len(call.kwargs["json"]["cve_ids"]) for call in mocked.call_args_list]
    assert sorted(sizes, reverse=True) == [50, 50, 20]


def test_fetch_cve_paas_graceful_on_network_error(monkeypatch, caplog):
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    with patch.object(reports.requests, "post",
                      side_effect=requests.ConnectionError("boom")):
        result = _fetch_cve_paas({"CVE-2024-0001"})
    assert result == {}  # graceful: empty rather than raising
    # warning is logged so operators can see what happened
    assert any("CVE-PaaS batch fetch failed" in r.message for r in caplog.records)


def test_fetch_cve_paas_graceful_on_5xx(monkeypatch):
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    bad = MagicMock()
    bad.raise_for_status.side_effect = requests.HTTPError("503 Service Unavailable")
    with patch.object(reports.requests, "post", return_value=bad):
        result = _fetch_cve_paas({"CVE-2024-0001"})
    assert result == {}


def test_fetch_cve_paas_graceful_on_malformed_json(monkeypatch):
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    bad = MagicMock()
    bad.raise_for_status = lambda: None
    bad.json.side_effect = ValueError("not json")
    with patch.object(reports.requests, "post", return_value=bad):
        result = _fetch_cve_paas({"CVE-2024-0001"})
    assert result == {}


def test_fetch_cve_paas_logs_per_cve_errors(monkeypatch, caplog):
    """ Batch may return per-CVE error records; we warn about them """
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    payload = {
        "CVE-2024-0001": {"Priority": "High", "Details": {}},
        "CVE-2024-0002": {"error": "vulnx error: Rate limit exceeded"},
        "CVE-2024-0003": {"error": "not found in vulnx response"},
    }
    with patch.object(reports.requests, "post",
                      return_value=_post_response(payload)):
        import logging
        with caplog.at_level(logging.WARNING, logger="backend.reports"):
            result = _fetch_cve_paas({"CVE-2024-0001", "CVE-2024-0002",
                                       "CVE-2024-0003"})
    # All three are kept in the result so downstream attach can see them
    assert set(result.keys()) == {"CVE-2024-0001", "CVE-2024-0002",
                                   "CVE-2024-0003"}
    # Warning lists the two errored ids
    warned = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert any("2 id(s)" in m and "CVE-2024-0002" in m for m in warned)


def test_fetch_cve_paas_partial_failure_returns_what_succeeded(monkeypatch):
    """ One batch fails, the next succeeds - return the successful slice """
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    cve_ids = {f"CVE-2024-{n:04d}" for n in range(75)}  # 2 batches: 50 + 25
    responses = [
        requests.ConnectionError("first batch down"),
        _post_response({"CVE-2024-0050": {"Priority": "Medium"}}),
    ]
    with patch.object(reports.requests, "post", side_effect=responses):
        result = _fetch_cve_paas(cve_ids)
    assert result == {"CVE-2024-0050": {"Priority": "Medium"}}


# Wider enrichment in _attach_vulnerabilities

def _components_with_one_cve():
    return {
        "c1": {
            "name": "libA",
            "version": "1.0",
            "vulnerabilities": [],
        },
    }


def _vuln_payload(cve_id):
    return [{
        "id": cve_id,
        "bom-ref": "v1",
        "ratings": [{"severity": "high"}],
        "affects": [{"ref": "c1"}],
    }]


def test_attach_vulnerabilities_surfaces_kev_in_add_info():
    components = _components_with_one_cve()
    # CVE-PaaS response shape: Links is a dict of URL strings.
    cve_paas_data = {
        "CVE-2024-0001": {
            "Priority": "Medium",
            "Details": {
                "is_exploited": True, "is_poc": False, "is_template": False,
                "Links": {
                    "KEV": "https://www.cisa.gov/kev/CVE-2024-0001",
                },
            },
        },
    }
    reports._attach_vulnerabilities(components, _vuln_payload("CVE-2024-0001"),
                                    {}, cve_paas_data)
    vulns = components["c1"]["vulnerabilities"]
    assert len(vulns) == 1
    v = vulns[0]
    assert v["is_kev"] is True
    assert "KEV: https://www.cisa.gov/kev/CVE-2024-0001" in v["add_info"]


def test_attach_vulnerabilities_surfaces_poc_and_nuclei():
    components = _components_with_one_cve()
    cve_paas_data = {
        "CVE-2024-0001": {
            "Priority": "Medium",  # not "Critical" - flags should still surface
            "Details": {
                "is_exploited": False, "is_poc": True, "is_template": True,
                "CVSS": 7.5, "EPSS": 0.123,
                "Links": {
                    "POC": "https://github.com/poc/exploit",
                    "Nuclei templates": "https://nuclei/lib",
                },
            },
        },
    }
    reports._attach_vulnerabilities(components, _vuln_payload("CVE-2024-0001"),
                                    {}, cve_paas_data)
    v = components["c1"]["vulnerabilities"][0]
    assert v["is_poc"] is True
    assert v["is_nuclei_template"] is True
    assert "POC: https://github.com/poc/exploit" in v["add_info"]
    assert "Nuclei: https://nuclei/lib" in v["add_info"]
    assert v["cvss"] == 7.5
    assert v["epss"] == 0.123


def test_attach_vulnerabilities_handles_null_links():
    """ CVE-PaaS returns Links: null when no flag is true """
    components = _components_with_one_cve()
    cve_paas_data = {
        "CVE-2024-0001": {
            "Priority": "Low",
            "Details": {
                "is_exploited": False, "is_poc": False, "is_template": False,
                "Links": None,
            },
        },
    }
    reports._attach_vulnerabilities(components, _vuln_payload("CVE-2024-0001"),
                                    {}, cve_paas_data)
    v = components["c1"]["vulnerabilities"][0]
    assert v["add_info"] == ""
    assert v["is_kev"] is False


def test_attach_vulnerabilities_no_enrichment_when_paas_silent():
    """ Without CVE-PaaS data, the new fields are absent / falsy """
    components = _components_with_one_cve()
    reports._attach_vulnerabilities(components, _vuln_payload("CVE-2024-0001"),
                                    {}, {})
    v = components["c1"]["vulnerabilities"][0]
    assert v["add_info"] == ""
    assert v["is_kev"] is False
    assert v["is_poc"] is False
    assert v["is_nuclei_template"] is False
    assert v["cvss"] is None
    assert v["epss"] is None


# Severity rollup when CVE-PaaS returns Undefined

def test_compute_severity_falls_back_to_severity_minus_one_for_undefined(monkeypatch):
    """ Priority == "undefined" -> downgrade severity by one tier """
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    components = {
        "c1": {
            "vulnerabilities": [
                {"severity": "high", "priority": "undefined"},
                {"severity": "medium", "priority": "undefined"},
            ],
            "severity": "", "severity_level": 0,
        },
    }
    reports._compute_severity(components)
    # max of high->medium (level 2) and medium->low (level 1) is medium
    assert components["c1"]["severity"] == "medium"
    assert components["c1"]["severity_level"] == 2


def test_compute_severity_low_stays_low_on_undefined(monkeypatch):
    """ low -> low (clamp, not down to info) """
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    components = {
        "c1": {"vulnerabilities": [{"severity": "low", "priority": "undefined"}],
               "severity": "", "severity_level": 0},
    }
    reports._compute_severity(components)
    assert components["c1"]["severity"] == "low"


def test_compute_severity_uses_priority_when_set(monkeypatch):
    """ Real priority wins over severity (existing behaviour, kept) """
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    components = {
        "c1": {"vulnerabilities": [{"severity": "low", "priority": "critical"}],
               "severity": "", "severity_level": 0},
    }
    reports._compute_severity(components)
    assert components["c1"]["severity"] == "critical"


def test_compute_severity_mixed_defined_and_undefined(monkeypatch):
    """ One CVE with real priority, one undefined: max wins """
    monkeypatch.setenv("CVEPAAS_URL", "https://cvepaas.example.com")
    components = {
        "c1": {
            "vulnerabilities": [
                {"severity": "high", "priority": "undefined"},  # -> medium
                {"severity": "low", "priority": "low"},         # -> low
            ],
            "severity": "", "severity_level": 0,
        },
    }
    reports._compute_severity(components)
    # max(medium, low) = medium
    assert components["c1"]["severity"] == "medium"
