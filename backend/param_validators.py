""" Module for validate and formatted parameters """
import requests
import urllib3
import validators

urllib3.disable_warnings()



def check_format_url(url):
    """ Check existence and format url to <protocol://domain/api/v1/> """
    if not validators.url(url):
        raise ValueError("URL not valid")
    url = url.split("/api/v")[0] + "/api/v1/"
    return url

def check_token(token, url):
    """ Check existence token and trying to connect to DT. Return correct headers """
    if not token:
        raise ValueError("Token not set")
    headers = {
        "X-Api-Key": token
    }
    res = requests.get(url+"project", headers=headers, verify=False, timeout=100)
    if res.status_code != 200:
        raise ConnectionError("Something wrong with connection. Check your parameters")
    return headers

def check_project(project):
    """ Check existence project """
    if not project:
        raise ValueError("Project not set")
    return project

def check_severities(severities):
    """ Check existence severities and values inside """
    if not severities:
        raise ValueError("Severities not set")
    for i in severities:
        if i not in ["critical", "high", "medium", "low", "unassigned"]:
            raise ValueError("Severities contain wrong value")
    return severities
