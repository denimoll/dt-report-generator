""" Tests for backend.projects.get_projects """

import json
from unittest.mock import MagicMock, patch

from backend import projects


def _ok(text, total=0):
    res = MagicMock()
    res.status_code = 200
    res.text = text
    res.json = lambda: json.loads(text)
    res.headers = {"X-Total-Count": str(total)}
    return res


def _check_token_ok(_token, _url):
    return {"X-Api-Key": "k"}


def _check_format_url(u):
    return "https://example.com/api/v1/"


def test_uuid_search_calls_per_project_endpoint():
    """ Typing a UUID hits /project/{uuid} not the list endpoint """
    captured = {}

    def fake_get(url, headers=None, verify=None, timeout=None):
        captured["url"] = url
        return _ok(json.dumps({"uuid": "00000000-0000-0000-0000-000000000001",
                               "name": "demo"}))

    with patch.object(projects, "check_format_url", _check_format_url), \
         patch.object(projects, "check_token", _check_token_ok), \
         patch.object(projects.requests, "get", side_effect=fake_get):
        body, total = projects.get_projects(
            "https://example.com", "tok",
            search_text="00000000-0000-0000-0000-000000000001",
        )
    assert captured["url"].endswith("/project/00000000-0000-0000-0000-000000000001")
    parsed = json.loads(body)
    assert parsed == [{"uuid": "00000000-0000-0000-0000-000000000001",
                       "name": "demo"}]
    assert total == 1


def test_uuid_search_returns_empty_on_404():
    """ Unknown UUID -> empty list, total 0 (dropdown shows no results) """
    not_found = MagicMock(status_code=404, text="")
    with patch.object(projects, "check_format_url", _check_format_url), \
         patch.object(projects, "check_token", _check_token_ok), \
         patch.object(projects.requests, "get", return_value=not_found):
        body, total = projects.get_projects(
            "https://example.com", "tok",
            search_text="ffffffff-ffff-ffff-ffff-ffffffffffff",
        )
    assert body == "[]"
    assert total == 0


def test_uuid_search_is_case_insensitive():
    captured = {}

    def fake_get(url, headers=None, verify=None, timeout=None):
        captured["url"] = url
        return _ok(json.dumps({"uuid": "DEAD", "name": "x"}))

    with patch.object(projects, "check_format_url", _check_format_url), \
         patch.object(projects, "check_token", _check_token_ok), \
         patch.object(projects.requests, "get", side_effect=fake_get):
        projects.get_projects(
            "https://example.com", "tok",
            search_text="ABCDEF12-3456-7890-ABCD-EF1234567890",
        )
    assert "ABCDEF12-3456-7890-ABCD-EF1234567890" in captured["url"]


def test_non_uuid_search_uses_list_endpoint():
    """ Plain text search still goes through /project?searchText=... """
    captured = {}

    def fake_get(url, headers=None, verify=None, timeout=None):
        captured["url"] = url
        return _ok("[]", total=0)

    with patch.object(projects, "check_format_url", _check_format_url), \
         patch.object(projects, "check_token", _check_token_ok), \
         patch.object(projects.requests, "get", side_effect=fake_get):
        projects.get_projects(
            "https://example.com", "tok", search_text="kafka",
        )
    assert "project?" in captured["url"]
    assert "searchText=kafka" in captured["url"]


def test_empty_search_still_uses_list_endpoint():
    captured = {}

    def fake_get(url, headers=None, verify=None, timeout=None):
        captured["url"] = url
        return _ok("[]", total=0)

    with patch.object(projects, "check_format_url", _check_format_url), \
         patch.object(projects, "check_token", _check_token_ok), \
         patch.object(projects.requests, "get", side_effect=fake_get):
        projects.get_projects("https://example.com", "tok", search_text="")
    assert "project?" in captured["url"]


def test_multi_token_search_sends_first_token_and_filters_client_side():
    """ "kafka 1.0" -> server search by "kafka", filter results by "1.0" """
    captured = {}
    body = json.dumps([
        {"name": "kafka", "version": "1.0", "uuid": "u1"},
        {"name": "kafka", "version": "1.5", "uuid": "u2"},
        {"name": "kafka-streams", "version": "1.0", "uuid": "u3"},
    ])

    def fake_get(url, headers=None, verify=None, timeout=None):
        captured["url"] = url
        return _ok(body, total=3)

    with patch.object(projects, "check_format_url", _check_format_url), \
         patch.object(projects, "check_token", _check_token_ok), \
         patch.object(projects.requests, "get", side_effect=fake_get):
        result_body, total = projects.get_projects(
            "https://example.com", "tok", search_text="kafka 1.0")
    # Server got just "kafka" — the version token is consumed client-side
    assert "searchText=kafka" in captured["url"]
    parsed = json.loads(result_body)
    # Filter keeps anything matching "1.0" in (name + " " + version) — that
    # is kafka 1.0 AND kafka-streams 1.0 (both contain "1.0" in version).
    versions = sorted(p["version"] for p in parsed)
    names = sorted(p["name"] for p in parsed)
    assert "1.0" in versions
    assert "kafka" in names
    assert total == len(parsed)


def test_multi_token_search_excludes_non_matches():
    body = json.dumps([
        {"name": "kafka", "version": "1.0", "uuid": "u1"},
        {"name": "kafka", "version": "2.0", "uuid": "u2"},
    ])
    with patch.object(projects, "check_format_url", _check_format_url), \
         patch.object(projects, "check_token", _check_token_ok), \
         patch.object(projects.requests, "get", return_value=_ok(body, total=2)):
        result_body, total = projects.get_projects(
            "https://example.com", "tok", search_text="kafka 1.0")
    parsed = json.loads(result_body)
    assert len(parsed) == 1
    assert parsed[0]["version"] == "1.0"
    assert total == 1
