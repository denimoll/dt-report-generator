""" Module for tasks with dependencyGraph """
# not snake_case cause DT use this naming

import json

import requests
import urllib3
from PrettyPrint import PrettyPrintTree

from backend.param_validators import check_format_url, check_token

urllib3.disable_warnings()

class Tree:
    def __init__(self, value):
        self.val = value
        self.children = []

    def add_child(self, child):
        self.children.append(child)
        return child


def get_graph(url, token, project, depth=3):
    """ Return dependency graph """
    # validate parameters
    url = check_format_url(url)
    headers = check_token(token, url)
    # 
    pt = PrettyPrintTree(
        lambda x: x.children,
        lambda x: x.val,
        color='',
        orientation=PrettyPrintTree.Horizontal,
        return_instead_of_print=True
    )
    tree = Tree("  Application  ")

    def udpate_directDependencies(directDependencies, depth):
        """ Recurs update dependencies """
        dependencies = []
        for dependency in directDependencies:
            dependencies.append({
                "name": dependency.get("name"),
                "version": dependency.get("version"),
                "latestVersion": dependency.get("latestVersion"),
                "vulnerabilities": json.loads(requests.get(url+
                    "vulnerability/component/"+dependency.get("uuid")+"?searchText=&pageSize=100&pageNumber=1",
                headers=headers, verify=False, timeout=100).text),
                "dependencies": udpate_directDependencies(json.loads(requests.get(url+
                    "dependencyGraph/component/"+dependency.get("uuid")+"/directDependencies",
                headers=headers, verify=False, timeout=100).text), depth-1) if depth else []
            })
        return dependencies
    
    def update_tree(tree, dependencies):
        """ Recurs update dependency tree """
        for dependency in dependencies:
            if dependency.get("vulnerabilities"):
                vuln_critical = set(x.get("severity") for x in dependency.get("vulnerabilities"))
                node_name = "  [VULNERABLE]  \n  %s@%s  \n  Severity: %s  \n  Update to %s version  " \
                            % (dependency.get("name"), dependency.get("version"), ", ".join(vuln_critical), dependency.get("latestVersion"))
            else:
                node_name = "  %s@%s  " % (dependency.get("name"), dependency.get("version"))
            d = tree.add_child(Tree(node_name))
            d_dependencies = dependency.get("dependencies")
            if d_dependencies:
                d = update_tree(d, d_dependencies)
        return tree

    req_dependencies = requests.get(url+"dependencyGraph/project/"+project+"/directDependencies",
        headers=headers, verify=False, timeout=100)
    directDependencies = json.loads(req_dependencies.text)
    if not directDependencies:
        return 0
    else:
        dependencies = udpate_directDependencies(directDependencies, depth-1)
        tree = update_tree(tree, dependencies)
        return pt(tree)
