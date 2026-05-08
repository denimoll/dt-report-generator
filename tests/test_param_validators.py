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
