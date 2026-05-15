""" Module for tasks with projects """

import json
import logging
import re
from urllib.parse import quote

import requests

from backend.param_validators import check_format_url, check_token, http_timeout, verify_tls

logger = logging.getLogger(__name__)

_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def get_projects(url, token, search_text="", page_size=99999, page_number=1):
    """ Fetch a page of DT projects.

    Search semantics:

    - Canonical UUID -> direct /project/<uuid> lookup. DT's list endpoint
      matches searchText only by name, so a typed UUID would return nothing.
    - Multi-token text (e.g. "kafka 1.0" or "<lockedName> 1.0") -> the first
      token goes to DT as searchText (name match), the remaining tokens are
      filtered client-side against "<name> <version>" so the dropdown can
      narrow by version too. Useful in diff mode when one project has many
      versions.
    - Single token -> existing behaviour (DT searchText).

    Returns a (body, total) tuple. On success body is the raw JSON text
    DT returned and total is the value of DT's X-Total-Count header.
    On failure body is an {"error": ...} dict and total is 0.
    """
    try:
        logger.debug("Starting project fetch")

        # validate parameters
        url = check_format_url(url)
        headers = check_token(token, url)
        text = (search_text or "").strip()

        if _UUID_PATTERN.fullmatch(text):
            # Direct per-project lookup. 404 means "no such uuid" and is
            # rendered as an empty list so the dropdown stays sane.
            uuid = text
            res = requests.get(
                f"{url}project/{uuid}",
                headers=headers, verify=verify_tls(), timeout=http_timeout(),
            )
            if res.status_code == 404:
                logger.debug(f"Project {uuid} not found in DT")
                return "[]", 0
            if res.status_code != 200:
                logger.warning(f"DT returned status {res.status_code} "
                               f"for project/{uuid}")
                return {"error": "Request to Dependency-Track failed"}, 0
            return json.dumps([res.json()]), 1

        tokens = text.split()
        primary = tokens[0] if tokens else ""
        extra_filters = [t.lower() for t in tokens[1:]]

        endpoint = (
            f"{url}project?excludeInactive=true&onlyRoot=false"
            f"&searchText={quote(primary)}"
            f"&sortName=lastBomImport&sortOrder=desc"
            f"&pageSize={page_size}&pageNumber={page_number}"
        )
        logger.debug(f"Sending request to: {endpoint}")

        # get projects
        res = requests.get(endpoint,
            headers=headers, verify=verify_tls(), timeout=http_timeout())
        if res.status_code != 200:
            logger.warning(f"DT returned status {res.status_code} for project list")
            return {"error": "Request to Dependency-Track failed"}, 0
        try:
            total = int(res.headers.get("X-Total-Count") or "0")
        except ValueError:
            total = 0

        if extra_filters:
            try:
                data = json.loads(res.text)
            except (TypeError, ValueError):
                return res.text, total
            filtered = []
            for project in data:
                haystack = (f"{project.get('name') or ''} "
                            f"{project.get('version') or ''}").lower()
                if all(tok in haystack for tok in extra_filters):
                    filtered.append(project)
            logger.debug(f"Client-side filter {extra_filters!r}: "
                         f"{len(data)} -> {len(filtered)}")
            return json.dumps(filtered), len(filtered)

        logger.debug(f"Fetched {res.text.count('uuid')} projects, total={total}")
        return res.text, total
    except requests.RequestException as e:
        logger.exception(f"Failed to fetch projects: {str(e)}")
        return {"error": "Request to Dependency-Track failed"}, 0
    except Exception as e:
        logger.exception(f"Unexpected error in get_projects: {str(e)}")
        return {"error": "Unexpected error while getting projects"}, 0
