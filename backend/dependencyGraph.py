""" Module for tasks with dependencyGraph """

import json

import requests
import urllib3

urllib3.disable_warnings()



def get_graph(url, headers, project, depth=3):
    def udpate_directDependencies(directDependencies, depth):
        dependencies = []
        for dependency in directDependencies:
            dependencies.append({
                "name": dependency.get("name"),
                "version": dependency.get("version"),
                "latestVersion": dependency.get("latestVersion"),
                "dependencies": udpate_directDependencies(json.loads(requests.get(url+"dependencyGraph/component/"+dependency.get("uuid")+"/directDependencies",
                headers=headers, verify=False, timeout=100).text), depth-1) if depth else []
            })
        return dependencies
    req_dependencies = requests.get(url+"dependencyGraph/project/"+project+"/directDependencies",
        headers=headers, verify=False, timeout=100)
    directDependencies = json.loads(req_dependencies.text)
    if not directDependencies:
        return 0
    else:
        return udpate_directDependencies(directDependencies, depth-1)
