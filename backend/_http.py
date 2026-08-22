""" Shared HTTP client for outbound DT / CVE-PaaS calls.

Wraps a single requests.Session with a Retry policy so transient 5xx
errors from DT or CVE-PaaS retry once before bubbling up. The facade
exposes get/post/RequestException so backend.* modules import a
single object and call it like the `requests` module - and existing
tests that patch `<module>.requests.get` keep working.
"""
import requests as _requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_retry = Retry(
    total=2,                     # 1 initial + 2 retries = 3 attempts
    backoff_factor=0.5,          # 0.5s, 1s
    status_forcelist=(502, 503, 504),
    allowed_methods=frozenset(["GET", "POST"]),
    raise_on_status=False,
)
_session = _requests.Session()
# Registering the adapter for the http:// scheme is not itself a plaintext
# request -- it only decides which transport handles one. On-prem DT / CVE-PaaS
# instances are routinely reachable over plain HTTP, and dropping this mount
# would silently disable retries for them.
_session.mount("http://", HTTPAdapter(max_retries=_retry))  # nosemgrep: python.lang.security.audit.insecure-transport.requests.request-session-with-http.request-session-with-http
_session.mount("https://", HTTPAdapter(max_retries=_retry))


class _Requests:
    """ Minimal requests-module facade. Instance attributes are settable
    so unit tests can patch `module.requests.get` exactly as before. """


requests = _Requests()
requests.get = _session.get
requests.post = _session.post
requests.RequestException = _requests.RequestException
