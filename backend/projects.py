""" Module for tasks with projects """

import requests
import urllib3
from backend.param_validators import (check_format_url, check_token)

urllib3.disable_warnings()



def get_projects(url, token):
    """ Return all projects from DT """
    # validate parameters
    url = check_format_url(url)
    headers = check_token(token, url)

    # get projects
    res = requests.get(url+
        "project?excludeInactive=true&onlyRoot=false&searchText=&\
        sortName=lastBomImport&sortOrder=desc&pageSize=99999&pageNumber=1",
        headers=headers, verify=False, timeout=1000)
    return res.text
