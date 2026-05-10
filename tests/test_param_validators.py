""" Tests for backend.param_validators """

from unittest.mock import MagicMock, patch

import pytest
import requests

from backend import param_validators as pv


# verify_tls / http_timeout

def test_verify_tls_default_true(monkeypatch):
    monkeypatch.delenv("DTRG_VERIFY_TLS", raising=False)
    assert pv.verify_tls() is True

@pytest.mark.parametrize("value", ["false", "False", "0", "no", "anything-else"])
def test_verify_tls_false_when_not_truthy(monkeypatch, value):
    monkeypatch.setenv("DTRG_VERIFY_TLS", value)
    assert pv.verify_tls() is False

@pytest.mark.parametrize("value", ["true", "True", "1", "t"])
def test_verify_tls_true_for_recognized_truthy(monkeypatch, value):
    monkeypatch.setenv("DTRG_VERIFY_TLS", value)
    assert pv.verify_tls() is True

def test_http_timeout_default(monkeypatch):
    monkeypatch.delenv("DTRG_HTTP_TIMEOUT", raising=False)
    assert pv.http_timeout() == 120

def test_http_timeout_explicit(monkeypatch):
    monkeypatch.setenv("DTRG_HTTP_TIMEOUT", "30")
    assert pv.http_timeout() == 30

def test_http_timeout_falls_back_on_garbage(monkeypatch):
    monkeypatch.setenv("DTRG_HTTP_TIMEOUT", "not-a-number")
    assert pv.http_timeout() == 120

def test_graph_depth_default(monkeypatch):
    monkeypatch.delenv("DTRG_GRAPH_DEPTH", raising=False)
    assert pv.graph_depth() == 3

def test_graph_depth_explicit(monkeypatch):
    monkeypatch.setenv("DTRG_GRAPH_DEPTH", "7")
    assert pv.graph_depth() == 7

def test_graph_depth_falls_back_on_garbage(monkeypatch):
    monkeypatch.setenv("DTRG_GRAPH_DEPTH", "deep")
    assert pv.graph_depth() == 3

def test_projects_page_size_default(monkeypatch):
    monkeypatch.delenv("DTRG_PROJECTS_PAGE_SIZE", raising=False)
    assert pv.projects_page_size() == 50

def test_projects_page_size_explicit(monkeypatch):
    monkeypatch.setenv("DTRG_PROJECTS_PAGE_SIZE", "200")
    assert pv.projects_page_size() == 200

def test_projects_page_size_falls_back_on_garbage(monkeypatch):
    monkeypatch.setenv("DTRG_PROJECTS_PAGE_SIZE", "many")
    assert pv.projects_page_size() == 50


# check_format_url

def test_check_format_url_appends_api_path():
    assert pv.check_format_url("https://dt.example.com") == "https://dt.example.com/api/v1/"

def test_check_format_url_normalises_existing_api_path():
    assert pv.check_format_url("https://dt.example.com/api/v2/") == "https://dt.example.com/api/v1/"

def test_check_format_url_rejects_invalid():
    with pytest.raises(ValueError, match="URL not valid"):
        pv.check_format_url("not a url")

def test_check_format_url_rejects_empty():
    with pytest.raises(ValueError, match="URL not valid"):
        pv.check_format_url("")


# DTRG_ALLOWED_HOSTS

def test_allowed_hosts_empty_when_env_unset(monkeypatch):
    monkeypatch.delenv("DTRG_ALLOWED_HOSTS", raising=False)
    assert pv.allowed_hosts() == []


def test_allowed_hosts_parses_comma_separated(monkeypatch):
    monkeypatch.setenv("DTRG_ALLOWED_HOSTS", "DT.example.com, *.dev.example.com ,host3")
    assert pv.allowed_hosts() == ["dt.example.com", "*.dev.example.com", "host3"]


def test_host_matches_exact():
    assert pv.host_matches("dt.example.com", "dt.example.com") is True
    assert pv.host_matches("dt.example.com", "DT.Example.COM") is True
    assert pv.host_matches("evil.com", "dt.example.com") is False


def test_host_matches_wildcard():
    assert pv.host_matches("a.example.com", "*.example.com") is True
    assert pv.host_matches("x.y.example.com", "*.example.com") is True
    # bare apex does NOT match a *.subdomain pattern
    assert pv.host_matches("example.com", "*.example.com") is False
    # similar-looking but different domain should not match
    assert pv.host_matches("a.example.com.evil.com", "*.example.com") is False


def test_check_format_url_passes_when_host_in_allowlist(monkeypatch):
    monkeypatch.setenv("DTRG_ALLOWED_HOSTS", "dt.example.com")
    assert pv.check_format_url("https://dt.example.com") == "https://dt.example.com/api/v1/"


def test_check_format_url_passes_with_wildcard(monkeypatch):
    monkeypatch.setenv("DTRG_ALLOWED_HOSTS", "*.example.com")
    assert pv.check_format_url("https://eu.dt.example.com") == \
        "https://eu.dt.example.com/api/v1/"


def test_check_format_url_rejects_host_outside_allowlist(monkeypatch):
    monkeypatch.setenv("DTRG_ALLOWED_HOSTS", "dt.example.com")
    with pytest.raises(ValueError, match="not allowed"):
        pv.check_format_url("https://169.254.169.254/")


def test_check_format_url_no_restriction_when_env_unset(monkeypatch):
    monkeypatch.delenv("DTRG_ALLOWED_HOSTS", raising=False)
    # any well-formed URL passes — allowlist disabled by default
    assert pv.check_format_url("https://internal.intranet") == \
        "https://internal.intranet/api/v1/"


# check_token

def _ok_response():
    res = MagicMock()
    res.status_code = 200
    res.text = "[]"
    return res

def test_check_token_returns_headers_on_success():
    with patch.object(pv.requests, "get", return_value=_ok_response()):
        assert pv.check_token("abc", "https://dt.example.com/api/v1/") == {"X-Api-Key": "abc"}

def test_check_token_rejects_empty():
    with pytest.raises(ValueError, match="Token not set"):
        pv.check_token("", "https://dt.example.com/api/v1/")

def test_check_token_raises_on_non_200():
    bad = MagicMock(status_code=401, text="unauthorized")
    with patch.object(pv.requests, "get", return_value=bad):
        with pytest.raises(ConnectionError, match="connection"):
            pv.check_token("abc", "https://dt.example.com/api/v1/")

def test_check_token_raises_on_network_error():
    with patch.object(pv.requests, "get", side_effect=requests.ConnectionError("boom")):
        with pytest.raises(ConnectionError, match="Failed to connect"):
            pv.check_token("abc", "https://dt.example.com/api/v1/")


# check_project

def test_check_project_returns_uuid():
    assert pv.check_project("00000000-0000-0000-0000-000000000000") == \
        "00000000-0000-0000-0000-000000000000"

def test_check_project_rejects_empty():
    with pytest.raises(ValueError, match="Project not set"):
        pv.check_project("")
