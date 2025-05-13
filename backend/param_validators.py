""" Module for validate and formatted parameters """
import logging

import requests
import urllib3
import validators

urllib3.disable_warnings()
logger = logging.getLogger(__name__)


def check_format_url(url: str) -> str:
    """ Check existence and format url to <protocol://domain/api/v1/> """
    logger.debug(f"Checking URL format: {url}")
    if not validators.url(url):
        logger.error(f"Invalid URL provided: {url}")
        raise ValueError("URL not valid")
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
        res = requests.get(url+"project", headers=headers, verify=False, timeout=100)
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
    logger.debug("Validating project: {project}")
    if not project:
        logger.error("Project not set")
        raise ValueError("Project not set")
    return project
