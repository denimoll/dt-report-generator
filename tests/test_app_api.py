""" Tests for the Flask app's HTTP routes (form + /api/v1/*) """

import json
from unittest.mock import MagicMock, patch

import pytest

import app as app_module


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("DTRG_API_KEY", "secret")
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as c:
        yield c


def test_index_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Get report" in response.data


# require_api_key

def test_api_reports_unauthorized_without_key(client):
    res = client.post("/api/v1/reports/get_report",
                      data=json.dumps({"project": "abc"}),
                      content_type="application/json")
    assert res.status_code == 401
    assert res.get_json() == {"error": "unauthorized"}


def test_api_reports_unauthorized_with_wrong_key(client):
    res = client.post("/api/v1/reports/get_report",
                      headers={"X-DTRG-Key": "wrong"},
                      data=json.dumps({"project": "abc"}),
                      content_type="application/json")
    assert res.status_code == 401


def test_api_reports_accepts_x_dtrg_key(client):
    """ Right key gets through auth (validation may still fail on missing URL) """
    res = client.post("/api/v1/reports/get_report",
                      headers={"X-DTRG-Key": "secret"},
                      data=json.dumps({"project": "abc"}),
                      content_type="application/json")
    # Past auth, fails on URL validation -> 400
    assert res.status_code == 400


def test_api_reports_accepts_bearer_token(client):
    res = client.post("/api/v1/reports/get_report",
                      headers={"Authorization": "Bearer secret"},
                      data=json.dumps({"project": "abc"}),
                      content_type="application/json")
    assert res.status_code == 400  # past auth, validator complains


def test_api_reports_open_when_env_unset(monkeypatch):
    """ Without DTRG_API_KEY the endpoint is open (private-network deploy) """
    monkeypatch.delenv("DTRG_API_KEY", raising=False)
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as c:
        res = c.post("/api/v1/reports/get_report",
                     data=json.dumps({"project": "abc"}),
                     content_type="application/json")
    # No auth required, validator still complains about URL
    assert res.status_code == 400


# /api/v1/projects

def test_api_projects_unauthorized_without_key(client):
    res = client.post("/api/v1/projects",
                      data=json.dumps({}),
                      content_type="application/json")
    assert res.status_code == 401


def test_api_projects_400_without_url_or_token(client):
    res = client.post("/api/v1/projects",
                      headers={"X-DTRG-Key": "secret"},
                      data=json.dumps({}),
                      content_type="application/json")
    assert res.status_code == 400
    assert "url and token" in res.get_json()["error"]


def test_api_projects_proxies_dt_response(client):
    """ With env defaults set, the endpoint forwards what get_projects returns """
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = json.dumps([{"name": "proj", "uuid": "u"}])
    with patch.object(app_module, "get_projects",
                      return_value=fake_response.text) as mocked:
        res = client.post("/api/v1/projects",
                          headers={"X-DTRG-Key": "secret"},
                          data=json.dumps({"url": "https://example.com",
                                           "token": "t"}),
                          content_type="application/json")
    assert res.status_code == 200
    assert res.headers["Content-Type"].startswith("application/json")
    assert mocked.called


def test_api_projects_502_when_get_projects_returns_error_dict(client):
    with patch.object(app_module, "get_projects",
                      return_value={"error": "Request to Dependency-Track failed"}):
        res = client.post("/api/v1/projects",
                          headers={"X-DTRG-Key": "secret"},
                          data=json.dumps({"url": "https://example.com",
                                           "token": "t"}),
                          content_type="application/json")
    assert res.status_code == 502
    assert res.get_json()["error"] == "Request to Dependency-Track failed"
