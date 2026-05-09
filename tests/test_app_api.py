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


def test_health_returns_status_and_version(client):
    """ /health is the Docker/k8s probe target. Must work without auth. """
    response = client.get("/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "ok"
    assert body["version"] == app_module.__version__


def test_health_does_not_require_api_key(monkeypatch):
    """ Probe must succeed even when DTRG_API_KEY is set. """
    monkeypatch.setenv("DTRG_API_KEY", "secret")
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as c:
        response = c.get("/health")  # no key supplied
    assert response.status_code == 200


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
    body = json.dumps([{"name": "proj", "uuid": "u"}])
    with patch.object(app_module, "get_projects",
                      return_value=(body, 1)) as mocked:
        res = client.post("/api/v1/projects",
                          headers={"X-DTRG-Key": "secret"},
                          data=json.dumps({"url": "https://example.com",
                                           "token": "t"}),
                          content_type="application/json")
    assert res.status_code == 200
    assert res.headers["Content-Type"].startswith("application/json")
    assert res.headers["X-Total-Count"] == "1"
    assert mocked.called


def test_api_projects_502_when_get_projects_returns_error_dict(client):
    with patch.object(app_module, "get_projects",
                      return_value=({"error": "Request to Dependency-Track failed"}, 0)):
        res = client.post("/api/v1/projects",
                          headers={"X-DTRG-Key": "secret"},
                          data=json.dumps({"url": "https://example.com",
                                           "token": "t"}),
                          content_type="application/json")
    assert res.status_code == 502
    assert res.get_json()["error"] == "Request to Dependency-Track failed"


def test_api_projects_forwards_pagination(client):
    body = json.dumps([])
    with patch.object(app_module, "get_projects",
                      return_value=(body, 0)) as mocked:
        client.post("/api/v1/projects",
                    headers={"X-DTRG-Key": "secret"},
                    data=json.dumps({"url": "https://example.com", "token": "t",
                                     "searchText": "kafka",
                                     "pageSize": 25, "pageNumber": 3}),
                    content_type="application/json")
    args, kwargs = mocked.call_args
    assert kwargs["search_text"] == "kafka"
    assert kwargs["page_size"] == 25
    assert kwargs["page_number"] == 3


def test_api_projects_default_page_size_is_unbounded(client):
    """ Backwards compat: CI users without pagination get the full list """
    body = json.dumps([])
    with patch.object(app_module, "get_projects",
                      return_value=(body, 0)) as mocked:
        client.post("/api/v1/projects",
                    headers={"X-DTRG-Key": "secret"},
                    data=json.dumps({"url": "https://example.com", "token": "t"}),
                    content_type="application/json")
    _, kwargs = mocked.call_args
    assert kwargs["page_size"] == 99999
    assert kwargs["page_number"] == 1


def test_api_projects_400_on_garbage_pagination(client):
    res = client.post("/api/v1/projects",
                      headers={"X-DTRG-Key": "secret"},
                      data=json.dumps({"url": "https://example.com", "token": "t",
                                       "pageSize": "many"}),
                      content_type="application/json")
    assert res.status_code == 400
    assert "integers" in res.get_json()["error"]


def test_form_projects_endpoint_paginates_with_env(monkeypatch):
    monkeypatch.delenv("DTRG_API_KEY", raising=False)
    monkeypatch.setenv("DTRG_PROJECTS_PAGE_SIZE", "25")
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    body = json.dumps([])
    with patch.object(app_module, "get_projects",
                      return_value=(body, 0)) as mocked:
        with app_module.app.test_client() as c:
            res = c.post("/projects/get_all",
                         data={"url": "https://example.com", "token": "t",
                               "searchText": "k", "pageNumber": "2"})
    app_module.app.config.update(WTF_CSRF_ENABLED=True)
    assert res.status_code == 200
    assert res.headers["X-Total-Count"] == "0"
    assert res.headers["X-Page-Size"] == "25"
    _, kwargs = mocked.call_args
    assert kwargs["page_size"] == 25
    assert kwargs["page_number"] == 2
    assert kwargs["search_text"] == "k"


# CSRF behaviour

def test_form_post_rejected_without_csrf_token(client):
    """ /reports/get_report and /projects/get_all are form endpoints under CSRF """
    res = client.post("/reports/get_report",
                      data={"url": "https://example.com", "token": "t",
                            "project": "demo (00000000-0000-0000-0000-000000000000)"})
    assert res.status_code == 400
    # The CSRF rejection message comes from flask-wtf, distinct from the API
    # endpoints' JSON error bodies.
    assert b"CSRF" in res.data or b"csrf" in res.data


def test_projects_form_endpoint_rejected_without_csrf_token(client):
    res = client.post("/projects/get_all",
                      data={"url": "https://example.com", "token": "t"})
    assert res.status_code == 400
    assert b"CSRF" in res.data or b"csrf" in res.data


def test_api_endpoints_remain_csrf_exempt(client):
    """ /api/v1/* must not require a CSRF token (CI flow) """
    res = client.post("/api/v1/projects",
                      headers={"X-DTRG-Key": "secret"},
                      data=json.dumps({}),
                      content_type="application/json")
    # 400 from input validation, NOT from CSRFProtect
    assert res.status_code == 400
    assert res.get_json()["error"] == "url and token are required"


# OpenAPI spec

def test_apispec_json_lists_api_routes(client):
    res = client.get("/apispec.json")
    assert res.status_code == 200
    spec = res.get_json()
    assert "/api/v1/reports/get_report" in spec["paths"]
    assert "/api/v1/projects" in spec["paths"]
    # Auth schemes are advertised
    assert "ApiKey" in spec["securityDefinitions"]
    assert "Bearer" in spec["securityDefinitions"]


def test_apidocs_ui_renders(client):
    res = client.get("/apidocs/")
    assert res.status_code == 200
    # Swagger UI ships a static index that mentions swagger
    assert b"swagger" in res.data.lower()


# /api/v1/reports/diff

def test_api_diff_unauthorized_without_key(client):
    res = client.post("/api/v1/reports/diff",
                      data=json.dumps({"projectA": "a", "projectB": "b"}),
                      content_type="application/json")
    assert res.status_code == 401


def test_api_diff_400_on_missing_url(client):
    """ Past auth, the resolver complains about empty URL """
    res = client.post("/api/v1/reports/diff",
                      headers={"X-DTRG-Key": "secret"},
                      data=json.dumps({"projectA": "a", "projectB": "b"}),
                      content_type="application/json")
    assert res.status_code == 400


def test_api_diff_passes_two_uuids_into_create_diff_report(client):
    """ Both project ids reach the backend's create_diff_report call """
    with patch.object(app_module, "create_diff_report",
                      return_value=("diff demo (07.05.2026)", None)) as mocked, \
         patch.object(app_module, "_create_zip",
                      return_value="/tmp/dtrg-x/reports.zip"), \
         patch.object(app_module, "send_file",
                      return_value=app_module.Response("", status=200,
                                                       mimetype="application/zip")):
        client.post("/api/v1/reports/diff",
                    headers={"X-DTRG-Key": "secret"},
                    data=json.dumps({"url": "https://example.com",
                                     "token": "t",
                                     "projectA": "uuid-a",
                                     "projectB": "uuid-b"}),
                    content_type="application/json")
    args, _ = mocked.call_args
    config_a, config_b, _ = args
    assert config_a["project"] == ["uuid-a"]
    assert config_b["project"] == ["uuid-b"]
    assert config_a["url"] == config_b["url"] == ["https://example.com"]
