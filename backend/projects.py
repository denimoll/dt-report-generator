import requests
import urllib3
import validators

urllib3.disable_warnings()



def get_projects(url, token):
    """Get all projects from DT"""
    # header for auth request
    headers = {
        'X-Api-Key': token
    }

    # format url to "protocol"://"domain"/api/v1/
    if not validators.url(url):
        raise ValueError('URL not valid')
    url = url.split('/api/v')[0] + '/api/v1/'
    res = requests.get(url+
        "project?excludeInactive=true&onlyRoot=false&searchText=&sortName=lastBomImport&sortOrder=desc&pageSize=99999&pageNumber=1",
        headers=headers, verify=False, timeout=1000)
    return res.text