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
