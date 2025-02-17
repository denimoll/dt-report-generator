""" Module for tasks with reports """

import json
from datetime import datetime

import requests
import urllib3
from docxtpl import DocxTemplate, RichText
from openpyxl import load_workbook

from backend.param_validators import check_format_url, check_project, check_token

urllib3.disable_warnings()



def get_severity(severities):
    """ Get level and name of severity by list severities """
    severity = {
        "unknown": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    level = max(list(severity[x] for x in severities))
    return level, [key for key, val in severity.items() if val == level][0]


def create_report(config):
    """ Create report from DT """
    # variables
    doc = DocxTemplate("reports/draft.docx") # docx template
    excel = load_workbook("reports/draft.xlsx") # excel document
    project_info = {} # common info about project
    components = {} # dict of components

    try:
        # read config and validate parameters
        url = check_format_url(config.get("url")[0])
        headers = check_token(config.get("token")[0], url)
        project = check_project(config.get("project")[0].split("(")[1].split(")")[0])

       # get common info about project
        res = requests.get(url+"project/"+project, headers=headers, verify=False, timeout=1000)
        text = json.loads(res.text)
        project_name = RichText()
        project_name_str = text.get("name")
        project_name.add(project_name_str,
            url_id=doc.build_url_id(url.split("api/v1/")[0]+"projects/"+project))
        project_info.update({
            "name": project_name,
            "version": text.get("version") or "no version",
            "lastBomImport": datetime.fromtimestamp(int(text.get("lastBomImport") or
                                                    0)/1000).strftime("%d.%m.%Y %H:%M"),
            "date": datetime.now().strftime("%d.%m.%Y %H:%M"),
            "componentsCount": text.get("metrics").get("components"),
            "vulnsCount": text.get("metrics").get("vulnerabilities"),
            "vulnComponentsCount": text.get("metrics").get("vulnerableComponents")
        })
        if text.get("directDependencies"):
            direct_dependencies = list(x.get("uuid")
                                    for x in json.loads(text.get("directDependencies")))
        else:
            direct_dependencies = []

        # get sbom with info about vulnerabilities and dependencies of dependencies
        res = requests.get(url+"bom/cyclonedx/project/"+project
                           +"?format=json&variant=withVulnerabilities&download=true",
                           headers=headers, verify=False, timeout=10000)
        text = json.loads(res.text)
        vulnerabilities = text.get("vulnerabilities")
        deps_deps = {}
        for deps in text.get("dependencies"):
            deps_deps.update({
                deps.get("ref"):deps.get("dependsOn")
            })

        # get components
        res = requests.get(url+"component/project/"+project+
            "?searchText=&pageSize=99999&pageNumber=1",
            headers=headers, verify=False, timeout=10000)
        for component in json.loads(res.text):
            try:
                last_version = component.get("repositoryMeta").get("latestVersion")
            except AttributeError:
                last_version = ""
            components.update({
                component.get("uuid"): {
                    "name": component.get("name"),
                    "version": component.get("version"),
                    "group": component.get("group") or "",
                    "last_version": last_version,
                    "is_direct_dependency": component.get("uuid") in direct_dependencies,
                    "dependencies": deps_deps[component.get("uuid")],
                    "vulnerabilities": [],
                    "severity": "",
                    "severity_level": 0,
                    "graph_level": 0
                }
            })

        # add info about vulnerabilities to components
        for vuln in vulnerabilities:
            for component in vuln.get("affects"):
                vuln_id = vuln.get("id")
                vuln_word_link = RichText()
                if vuln_id.lower().find("cve") != -1:
                    vuln_link = "https://nvd.nist.gov/vuln/detail/"+vuln_id
                    vuln_word_link.add(vuln_id, url_id=doc.build_url_id(vuln_link))
                elif vuln_id.lower().find("ghsa") != -1:
                    vuln_link = "https://github.com/advisories/"+vuln_id
                    vuln_word_link.add(vuln_id, url_id=doc.build_url_id(vuln_link))
                else:
                    vuln_link = vuln_id
                    vuln_word_link = vuln_id
                severity_level, severity = get_severity(list(x.get("severity")
                                                             for x in vuln.get("ratings")))
                components[component.get("ref")]["vulnerabilities"].append({
                    "uuid": vuln.get("bom-ref"),
                    "id": vuln_id,
                    "link": vuln_link,
                    "word_link": vuln_word_link,
                    "severity": severity,
                    "severity_level": severity_level
                })

        # set severity to vulnerable components
        for component, value in components.items():
            vulns = value.get("vulnerabilities")
            if vulns:
                severity_level, severity = get_severity(list(x.get("severity")
                                                             for x in vulns))
                components[component]["severity"] = severity
                components[component]["severity_level"] = severity_level
        vuln_components = {k: v for k, v in components.items() if v.get("vulnerabilities")}
        vuln_components = list((dict(sorted(vuln_components.items(),
                                      key=lambda item: item[1]["severity_level"],
                                      reverse=True))).values())

        # render and save result in word report
        doc.render({
            "project": project_info,
            "components": vuln_components
        })
        doc.save("reports/result.docx")

        # render and save result in excel report
        ws1 = excel["General information"]
        ws1["D2"].value = project_name_str + " (version: " + project_info.get("version") + ")"
        ws1["D2"].hyperlink = url.split("api/v1/")[0]+"projects/"+project
        ws1["D3"] = project_info.get("componentsCount")
        ws1["D4"] = project_info.get("vulnsCount")
        ws1["D5"] = project_info.get("vulnComponentsCount")
        ws1["D6"] = project_info.get("lastBomImport")
        ws1["D7"] = project_info.get("date")
        ws2 = excel["Vulnerable dependencies"]
        ws3 = excel["All issues"]
        vuln_num = 0
        for num, component in enumerate(vuln_components):
            ws2.cell(row=num+2, column=1, value=num+1)
            ws2.cell(row=num+2, column=2, value=component.get("name"))
            ws2.cell(row=num+2, column=3, value=str(component.get("version")))
            ws2.cell(row=num+2, column=4, value=component.get("group"))
            ws2.cell(row=num+2, column=5, value=str(component.get("severity")))
            ws2.cell(row=num+2, column=6, value=str(component.get("last_version")))
            for vuln in component.get("vulnerabilities"):
                ws3.cell(row=num+2+vuln_num, column=1, value=num+1+vuln_num)
                ws3.cell(row=num+2+vuln_num, column=2, value=vuln.get("id"))
                if isinstance(vuln.get("word_link"), RichText):
                    ws3.cell(row=num+2+vuln_num, column=2).hyperlink=vuln.get("link")
                ws3.cell(row=num+2+vuln_num, column=3, value=vuln.get("severity"))
                ws3.cell(row=num+2+vuln_num, column=4, value=component.get("name"))
                ws3.cell(row=num+2+vuln_num, column=5, value=component.get("version"))
                vuln_num += 1
            vuln_num -= 1
        excel.save("reports/result.xlsx")

        # return
        return f"{config.get('project')[0].split(' ')[0]} {project_info.get('version')} \
        ({datetime.now().strftime('%d.%m.%Y')})", components
    except (ValueError, ConnectionError) as e:
        return e
