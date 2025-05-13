""" Module for tasks with projects """

import logging

import requests
import urllib3

from backend.param_validators import check_format_url, check_token

urllib3.disable_warnings()
logger = logging.getLogger(__name__)


def get_projects(url, token):
    """ Return all projects from DT """
    try:
        logger.debug("Starting project fetch")
        
        # validate parameters
        url = check_format_url(url)
        if not isinstance(url, str):
            return url
        headers = check_token(token, url)
        if not isinstance(headers, dict):
            return headers
        
        endpoint = (
            f"{url}project?excludeInactive=true&onlyRoot=false&searchText=&"
            "sortName=lastBomImport&sortOrder=desc&pageSize=99999&pageNumber=1"
        )
        logger.debug("Sending request to: {endpoint}")

        # get projects
        res = requests.get(endpoint,
            headers=headers, verify=False, timeout=1000)
        logger.debug(f"Successfully fetched projects, status code: {res.status_code}")
        return res.text
    except requests.RequestException as e:
        logger.exception(f"Failed to fetch projects: {str(e)}")
        return {"error": "Request to Dependency-Track failed"}
    except Exception as e:
        logger.exception(f"Unexpected error in get_projects: {str(e)}")
        return {"error": "Unexpected error while getting projects"}
