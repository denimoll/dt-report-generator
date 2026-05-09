""" Tests for form.GetReportForm """

import app as app_module
from form import GetReportForm


def _form_in_context():
    """ FlaskForm needs an app context to render """
    with app_module.app.test_request_context("/"):
        return GetReportForm()


def test_url_field_writable_when_env_unset(monkeypatch):
    monkeypatch.delenv("DTRG_URL", raising=False)
    monkeypatch.delenv("DTRG_TOKEN", raising=False)
    form = _form_in_context()
    assert form.url.render_kw in (None, {})
    assert form.token.render_kw in (None, {})


def test_url_field_locked_when_dtrg_url_set(monkeypatch):
    monkeypatch.setenv("DTRG_URL", "https://dt.example.com")
    monkeypatch.delenv("DTRG_TOKEN", raising=False)
    form = _form_in_context()
    assert form.url.render_kw is not None
    assert form.url.render_kw.get("readonly") is True
    assert form.token.render_kw in (None, {})


def test_token_field_locked_when_dtrg_token_set(monkeypatch):
    monkeypatch.delenv("DTRG_URL", raising=False)
    monkeypatch.setenv("DTRG_TOKEN", "abc")
    form = _form_in_context()
    assert form.token.render_kw is not None
    assert form.token.render_kw.get("readonly") is True


def test_env_change_takes_effect_on_next_form(monkeypatch):
    """ Per-request reading: flipping the env between forms is visible """
    monkeypatch.delenv("DTRG_URL", raising=False)
    first = _form_in_context()
    assert first.url.render_kw in (None, {})

    monkeypatch.setenv("DTRG_URL", "https://dt.example.com")
    second = _form_in_context()
    assert second.url.render_kw.get("readonly") is True
