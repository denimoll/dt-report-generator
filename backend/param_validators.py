""" Module for validate and formatted parameters """
import logging
import os
from urllib.parse import urlparse

import urllib3
import validators

from backend._http import requests

logger = logging.getLogger(__name__)


def verify_tls() -> bool:
    """ Whether outbound HTTPS calls should verify the TLS certificate """
    return os.getenv("DTRG_VERIFY_TLS", "true").lower() in ["true", "1", "t"]


def http_timeout() -> int:
    """ Timeout in seconds for outbound HTTP calls to DT and CVE-PaaS """
    try:
        return int(os.getenv("DTRG_HTTP_TIMEOUT", "120"))
    except ValueError:
        return 120


def graph_depth() -> int:
    """ Default depth for the dependency graph traversal """
    try:
        return int(os.getenv("DTRG_GRAPH_DEPTH", "3"))
    except ValueError:
        return 3


def projects_page_size() -> int:
    """ Page size for the form's project dropdown (lazy-loaded from DT) """
    try:
        return int(os.getenv("DTRG_PROJECTS_PAGE_SIZE", "50"))
    except ValueError:
        return 50


def allowed_hosts() -> list[str]:
    """ Parse DTRG_ALLOWED_HOSTS into a list of lower-cased patterns.

    Empty list means no restriction (current default — any host is accepted).
    Patterns can be exact hostnames (`dt.example.com`) or wildcards
    (`*.example.com`, matches one or more labels in front of `.example.com`).
    """
    raw = os.getenv("DTRG_ALLOWED_HOSTS", "")
    return [h.strip().lower() for h in raw.split(",") if h.strip()]


def host_matches(host: str, pattern: str) -> bool:
    """ Match a hostname against a single allowlist pattern (case-insensitive).

    `*.example.com` matches `a.example.com` and `x.y.example.com` but NOT
    `example.com` itself. Plain patterns require exact equality.
    """
    if not host:
        return False
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


if not verify_tls():
    urllib3.disable_warnings()


def check_format_url(url: str) -> str:
    """ Check existence and format url to <protocol://domain/api/v1/> """
    logger.debug(f"Checking URL format: {url}")
    if not validators.url(url):
        logger.error(f"Invalid URL provided: {url}")
        raise ValueError("URL not valid")
    # SSRF allowlist: when DTRG_ALLOWED_HOSTS is set, the URL host must
    # match one of the patterns. The default empty list keeps the old
    # "any host" behaviour for the on-prem case.
    patterns = allowed_hosts()
    if patterns:
        host = (urlparse(url).hostname or "").lower()
        if not any(host_matches(host, p) for p in patterns):
            logger.warning(f"URL host {host!r} is not in DTRG_ALLOWED_HOSTS")
            raise ValueError("URL host not allowed")
    url = url.split("/api/v")[0] + "/api/v1/"
    logger.debug(f"Formatted URL: {url}")
    return url

def check_token(token: str, url: str) -> dict[str, str]:
    """ Check existence token and trying to connect to DT. Return correct headers """
    logger.debug(f"Validating token for URL: {url}")
    if not token:
        logger.error("Token not set")
        raise ValueError("Token not set")
    headers = {
        "X-Api-Key": token
    }
    try:
        res = requests.get(url+"project", headers=headers,
                           verify=verify_tls(), timeout=http_timeout())
        if res.status_code != 200:
            logger.warning(f"Connection failed. Status: {res.status_code}, Response: {res.text}")
            raise ConnectionError("Something wrong with connection. Check your parameters")
    except requests.RequestException as e:
        logger.exception(f"Exception occurred while checking token: {str(e)}")
        raise ConnectionError("Failed to connect to server")
    logger.debug("Token validated successfully")
    return headers

def check_project(project: str) -> str:
    """ Check existence project """
    logger.debug(f"Validating project: {project}")
    if not project:
        logger.error("Project not set")
        raise ValueError("Project not set")
    return project
