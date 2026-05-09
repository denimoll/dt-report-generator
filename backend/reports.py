""" Module for tasks with reports """

import json
import logging
import os
import re
from datetime import datetime

import requests
from docxtpl import DocxTemplate, RichText
from openpyxl import load_workbook
from openpyxl.styles import Alignment

from backend.dependency_graph import compute_graph_levels
from backend.param_validators import (
    check_format_url,
    check_project,
    check_token,
    http_timeout,
    verify_tls,
)

logger = logging.getLogger(__name__)



SUMMARY_SCHEMA_VERSION = 1


def _build_summary(project_name_str, project_url, project_info, vuln_components):
    """ Machine-readable companion to the docx/xlsx report.

    Produced as summary.json inside the ZIP so CI pipelines can post-process
    the report (severity gates, dashboards, ...) without parsing Office files.
    Kept intentionally flat - one component per entry, vulnerabilities nested
    inline - and only exposes JSON-serializable fields.
    """
    return {
        "schemaVersion": SUMMARY_SCHEMA_VERSION,
        "project": {
            "name": project_name_str,
            "version": project_info.get("version"),
            "url": project_url,
            "lastBomImport": project_info.get("lastBomImport"),
            "generatedAt": project_info.get("date"),
            "componentsCount": project_info.get("componentsCount"),
            "vulnerableComponentsCount": project_info.get("vulnComponentsCount"),
            "vulnerabilitiesCount": project_info.get("vulnsCount"),
            "suppressedCount": project_info.get("suppressedCount", 0),
        },
        "components": [
            {
                "name": c.get("name"),
                "version": c.get("version"),
                "group": c.get("group"),
                "lastVersion": c.get("last_version"),
                "isDirectDependency": c.get("is_direct_dependency"),
                "graphLevel": c.get("graph_level"),
                "severity": c.get("severity"),
                "vulnerabilities": [
                    {
                        "id": v.get("id"),
                        "link": v.get("link"),
                        "severity": v.get("severity"),
                        "priority": v.get("priority"),
                        "addInfo": v.get("add_info"),
                        "analysisState": v.get("analysis_state"),
                        "analysisJustification": v.get("analysis_justification"),
                        "analysisResponse": v.get("analysis_response"),
                        "analysisDetail": v.get("analysis_detail"),
                        "isSuppressed": v.get("is_suppressed"),
                    }
                    for v in c.get("vulnerabilities") or []
                ],
            }
            for c in vuln_components
        ],
    }


def get_severity(severities):
    """ Get level and name of severity by list severities """
    severity = {
        "unknown": 0,
        "undefined": 0,
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    level = max(severity.get((x or "").lower(), 0) for x in severities)
    return level, [key for key, val in severity.items() if val == level][0]


def _resolve_params(config):
    """ Pull url/token/project out of the request config, validate them """
    raw_url = os.getenv("DTRG_URL") or (config.get("url") or [""])[0]
    url = check_format_url(raw_url)
    token = os.getenv("DTRG_TOKEN") or (config.get("token") or [""])[0]
    headers = check_token(token, url)
    project_raw = (config.get("project") or [""])[0]
    # form flow sends "name version (uuid)"; API flow sends a bare UUID
    project_match = re.search(r"\(([^()]+)\)\s*$", project_raw)
    project_id = project_match.group(1) if project_match else project_raw.strip()
    project = check_project(project_id)
    return url, headers, project


def _fetch_project_info(url, headers, project):
    """ Read project metadata from DT and shape it for the report """
    logger.info("Fetching project metadata")
    res = requests.get(url+"project/"+project, headers=headers,
                       verify=verify_tls(), timeout=http_timeout())
    res.raise_for_status()
    text = res.json()
    project_name_str = text.get("name")
    metrics = text.get("metrics") or {}
    project_info = {
        # Plain string here; the docx render step decorates it as a hyperlink
        "name": project_name_str,
        "version": text.get("version") or "no version",
        "lastBomImport": datetime.fromtimestamp(int(text.get("lastBomImport") or
                                                0)/1000).strftime("%d.%m.%Y %H:%M"),
        "date": datetime.now().strftime("%d.%m.%Y %H:%M"),
        "componentsCount": metrics.get("components"),
        "vulnsCount": metrics.get("vulnerabilities"),
        "vulnComponentsCount": metrics.get("vulnerableComponents"),
    }
    logger.debug(f"Project info retrieved: {project_info}")
    if text.get("directDependencies"):
        direct_uuids = [x.get("uuid")
                        for x in json.loads(text.get("directDependencies"))]
    else:
        direct_uuids = []
    return project_info, project_name_str, direct_uuids


def _fetch_sbom(url, headers, project):
    """ Pull the CycloneDX SBOM (vulnerabilities + dependency graph) """
    logger.info("Fetching SBOM with vulnerabilities")
    res = requests.get(url+"bom/cyclonedx/project/"+project
                       +"?format=json&variant=withVulnerabilities&download=true",
                       headers=headers, verify=verify_tls(), timeout=http_timeout())
    res.raise_for_status()
    text = res.json()
    vulnerabilities = text.get("vulnerabilities") or []
    deps_deps = {}
    for deps in text.get("dependencies") or []:
        deps_deps[deps.get("ref")] = deps.get("dependsOn")
    return vulnerabilities, deps_deps


def _fetch_findings(url, headers, project):
    """ Pull VEX analysis from the findings API.

    The CycloneDX variant=withVulnerabilities does not always carry the
    analysis block (depends on DT version and how the VEX was imported);
    findings is the source of truth for the audit state shown in the DT UI.
    Returns a (vuln_id, component_uuid) -> analysis dict map.
    """
    logger.info("Fetching VEX analysis from findings API")
    res = requests.get(url+"finding/project/"+project+"?suppressed=true",
                       headers=headers, verify=verify_tls(), timeout=http_timeout())
    res.raise_for_status()
    analysis_by_pair = {}
    for finding in res.json() or []:
        vuln_id = (finding.get("vulnerability") or {}).get("vulnId")
        component_uuid = (finding.get("component") or {}).get("uuid")
        analysis = finding.get("analysis") or {}
        if vuln_id and component_uuid:
            analysis_by_pair[(vuln_id, component_uuid)] = {
                "state": (analysis.get("state") or "").lower(),
                "justification": analysis.get("justification") or "",
                "is_suppressed": bool(analysis.get("isSuppressed")),
            }
    logger.info(f"Findings API returned analysis for "
                f"{len(analysis_by_pair)} (vuln, component) pairs")
    return analysis_by_pair


def _fetch_components(url, headers, project, direct_uuids, deps_deps):
    """ Pull every component of the project and shape it for the report """
    res = requests.get(url+"component/project/"+project+
        "?searchText=&pageSize=99999&pageNumber=1",
        headers=headers, verify=verify_tls(), timeout=http_timeout())
    res.raise_for_status()
    components = {}
    for component in res.json():
        try:
            last_version = component.get("repositoryMeta").get("latestVersion")
        except AttributeError:
            last_version = ""
        components[component.get("uuid")] = {
            "name": component.get("name"),
            "version": component.get("version"),
            "group": component.get("group") or "",
            "last_version": last_version,
            "is_direct_dependency": component.get("uuid") in direct_uuids,
            "dependencies": deps_deps[component.get("uuid")],
            "vulnerabilities": [],
            "severity": "",
            "severity_level": 0,
            "graph_level": None,
        }
    logger.info(f"{len(components)} components processed")
    return components


_SUPPRESSED_STATES = {"resolved", "resolved_with_pedigree",
                      "false_positive", "not_affected"}


def _attach_vulnerabilities(components, vulnerabilities, analysis_by_pair, doc):
    """ Distribute vulnerabilities across components, with VEX + CVE-PaaS data.

    For every (vuln, affected component) pair we resolve the analysis state
    (findings API wins, SBOM block is the fallback for response/detail),
    build the per-vuln link, optionally enrich the entry from CVE-PaaS for
    canonical CVE ids, and append the result to the component's
    vulnerabilities list. The doc handle is needed for docxtpl's hyperlink
    builder.
    """
    logger.info("Processing component vulnerabilities")
    for vuln in vulnerabilities:
        sbom_analysis = vuln.get("analysis") or {}
        sbom_state = (sbom_analysis.get("state") or "").lower()
        sbom_justification = sbom_analysis.get("justification") or ""
        analysis_response = ", ".join(sbom_analysis.get("response") or [])
        analysis_detail = sbom_analysis.get("detail") or ""
        for component in vuln.get("affects"):
            vuln_id = vuln.get("id")
            component_ref = component.get("ref")
            # Findings API wins over the SBOM analysis block; SBOM is
            # the fallback for response/detail (findings does not expose those).
            finding_analysis = analysis_by_pair.get((vuln_id, component_ref), {})
            analysis_state = finding_analysis.get("state") or sbom_state
            analysis_justification = (finding_analysis.get("justification")
                                      or sbom_justification)
            is_suppressed = (
                finding_analysis.get("is_suppressed", False)
                or analysis_state in _SUPPRESSED_STATES
            )
            vuln_word_link = RichText()
            if "cve" in vuln_id.lower():
                vuln_link = "https://nvd.nist.gov/vuln/detail/"+vuln_id
                vuln_word_link.add(vuln_id, url_id=doc.build_url_id(vuln_link))
                # only canonical CVE-YYYY-NNNN ids may flow into the CVE-PaaS URL
                cve_id = vuln_id if re.fullmatch(r"CVE-\d{4}-\d{4,7}",
                                                 vuln_id, re.IGNORECASE) else ""
            elif "ghsa" in vuln_id.lower():
                vuln_link = "https://github.com/advisories/"+vuln_id
                vuln_word_link.add(vuln_id, url_id=doc.build_url_id(vuln_link))
# https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28
                cve_id = ""
            else:
                vuln_link = vuln_id
                vuln_word_link = vuln_id
                cve_id = ""
            severity_level, severity = get_severity(list(x.get("severity")
                                                         for x in vuln.get("ratings")))
            cve_paas = json.loads(requests.get(os.getenv("CVEPAAS_URL")+"/get_info/"+cve_id,
              verify=verify_tls(), timeout=http_timeout()).text) \
              if os.getenv("CVEPAAS_URL") and cve_id else {}
            add_info = []
            if cve_paas.get("Priority") and cve_paas.get("Priority").lower() == "critical":
                links = cve_paas["Details"]["Links"]
                for link in links.get("POC"):
                    add_info.append(link.get("url"))
                if links.get("Nuclei templates"):
                    add_info.append(links["Nuclei templates"].get("template_url"))
            components[component_ref]["vulnerabilities"].append({
                "uuid": vuln.get("bom-ref"),
                "id": vuln_id,
                "link": vuln_link,
                "word_link": vuln_word_link,
                "severity": severity,
                "severity_level": severity_level,
                "priority": cve_paas.get("Priority") or severity,
                "add_info": ", ".join(sorted(set(add_info))),
                "analysis_state": analysis_state,
                "analysis_justification": analysis_justification,
                "analysis_response": analysis_response,
                "analysis_detail": analysis_detail,
                "is_suppressed": is_suppressed,
            })
    logger.info("Vulnerabilities assigned to components")


def _filter_suppressed(components, project_info):
    """ Drop VEX-suppressed vulns unless DTRG_INCLUDE_SUPPRESSED is set.

    Mutates components in place. Records the count of dropped (or kept,
    when included) findings on project_info["suppressedCount"].
    """
    include_suppressed = os.getenv("DTRG_INCLUDE_SUPPRESSED",
                                   "false").lower() in ["true", "1", "t"]
    suppressed_count = 0
    for value in components.values():
        kept = []
        for vuln in value["vulnerabilities"]:
            if vuln["is_suppressed"]:
                suppressed_count += 1
                if not include_suppressed:
                    continue
            kept.append(vuln)
        value["vulnerabilities"] = kept
    project_info["suppressedCount"] = suppressed_count
    logger.info(f"VEX-suppressed vulnerabilities: {suppressed_count} "
                f"(included in report: {include_suppressed})")


def _compute_severity(components):
    """ Roll up the per-component severity from its remaining vulns """
    logger.info("Computing final severity levels for components")
    use_priority = bool(os.getenv("CVEPAAS_URL"))
    for value in components.values():
        vulns = value.get("vulnerabilities")
        if not vulns:
            continue
        if use_priority:
            severity_level, severity = get_severity(list(x.get("priority").lower()
                                                         for x in vulns))
        else:
            severity_level, severity = get_severity(list(x.get("severity")
                                                         for x in vulns))
        value["severity"] = severity
        value["severity_level"] = severity_level


def _sort_vulnerable(components):
    """ Return components that have vulns, sorted high-severity first """
    vuln_components = {k: v for k, v in components.items() if v.get("vulnerabilities")}
    return list(dict(sorted(vuln_components.items(),
                            key=lambda item: item[1]["severity_level"],
                            reverse=True)).values())


def _render_docx(doc, project_info, project_name_str, project_url,
                 vuln_components, output_dir):
    """ Render the Word report into output_dir/result.docx """
    logger.info("Generating Word report")
    # decorate the project name with a hyperlink only at render time, so the
    # data layer above stays free of docxtpl-specific objects
    project_for_render = dict(project_info)
    project_link = RichText()
    project_link.add(project_name_str, url_id=doc.build_url_id(project_url))
    project_for_render["name"] = project_link
    doc.render({
        "project": project_for_render,
        "components": vuln_components,
    })
    doc.save(os.path.join(output_dir, "result.docx"))
    logger.info("Word report saved")


def _render_xlsx(excel, project_info, project_name_str, project_url,
                 vuln_components, output_dir):
    """ Render the Excel report into output_dir/result.xlsx """
    logger.info("Generating Excel report")
    ws1 = excel["General information"]
    ws1["D2"].value = (project_name_str + " (version: "
                       + project_info.get("version") + ")")
    ws1["D2"].hyperlink = project_url
    ws1["D3"] = project_info.get("componentsCount")
    ws1["D4"] = project_info.get("vulnsCount")
    ws1["D5"] = project_info.get("vulnComponentsCount")
    ws1["D6"] = project_info.get("lastBomImport")
    ws1["D7"] = project_info.get("date")
    if not vuln_components:
        del excel["Vulnerable dependencies"]
        del excel["All issues"]
        excel.save(os.path.join(output_dir, "result.xlsx"))
        logger.info("Excel report saved")
        return
    ws2 = excel["Vulnerable dependencies"]
    ws3 = excel["All issues"]
    vuln_num = 0
    for num, component in enumerate(vuln_components):
        ws2.cell(row=num+2, column=1, value=num+1)
        ws2.cell(row=num+2, column=2, value=component.get("name"))
        ws2.cell(row=num+2, column=3, value=str(component.get("version")))
        ws2.cell(row=num+2, column=4, value=component.get("group"))
        if component.get("is_direct_dependency"):
            final_severity = f"{str(component.get('severity'))} in direct dependency"
        else:
            final_severity = str(component.get("severity"))
        ws2.cell(row=num+2, column=5, value=final_severity)
        ws2.cell(row=num+2, column=6, value=str(component.get("last_version")))
        graph_level = component.get("graph_level")
        ws2.cell(row=num+2, column=7,
                 value="" if graph_level is None else graph_level)
        for vuln in component.get("vulnerabilities"):
            ws3.cell(row=num+2+vuln_num, column=1, value=num+1+vuln_num)
            ws3.cell(row=num+2+vuln_num, column=2, value=vuln.get("id"))
            if isinstance(vuln.get("word_link"), RichText):
                ws3.cell(row=num+2+vuln_num, column=2).hyperlink = vuln.get("link")
            ws3.cell(row=num+2+vuln_num, column=3, value=vuln.get("severity"))
            ws3.cell(row=num+2+vuln_num, column=4,
                     value=(vuln.get("priority") or "").lower())
            ws3.cell(row=num+2+vuln_num, column=5, value=component.get("name"))
            ws3.cell(row=num+2+vuln_num, column=6, value=component.get("version"))
            ws3.cell(row=num+2+vuln_num, column=7, value=vuln.get("add_info"))
            ws3.cell(row=num+2+vuln_num, column=7).alignment = Alignment(wrap_text=True)
            ws3.cell(row=num+2+vuln_num, column=8,
                     value=vuln.get("analysis_state") or "")
            vuln_num += 1
        vuln_num -= 1
    excel.save(os.path.join(output_dir, "result.xlsx"))
    logger.info("Excel report saved")


def _render_summary(project_name_str, project_url, project_info,
                    vuln_components, output_dir):
    """ Write the JSON summary alongside the docx/xlsx """
    summary = _build_summary(project_name_str, project_url,
                             project_info, vuln_components)
    with open(os.path.join(output_dir, "summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    logger.info("JSON summary saved")


def create_report(config, output_dir):
    """ Create report from DT into the per-request output_dir """
    logger.info("Report generation started")
    doc = DocxTemplate("reports/draft.docx")
    excel = load_workbook("reports/draft.xlsx")

    try:
        url, headers, project = _resolve_params(config)
        project_info, project_name_str, direct_uuids = _fetch_project_info(
            url, headers, project)
        vulnerabilities, deps_deps = _fetch_sbom(url, headers, project)
        analysis_by_pair = _fetch_findings(url, headers, project)
        components = _fetch_components(url, headers, project,
                                       direct_uuids, deps_deps)

        _attach_vulnerabilities(components, vulnerabilities, analysis_by_pair, doc)
        _filter_suppressed(components, project_info)
        _compute_severity(components)
        vuln_components = _sort_vulnerable(components)
        logger.info(f"{len(vuln_components)} vulnerable components found")
        compute_graph_levels(components)

        project_url = url.split("api/v1/")[0] + "projects/" + project
        _render_docx(doc, project_info, project_name_str, project_url,
                     vuln_components, output_dir)
        _render_xlsx(excel, project_info, project_name_str, project_url,
                     vuln_components, output_dir)
        _render_summary(project_name_str, project_url, project_info,
                        vuln_components, output_dir)

        report_name = project_name_str or project
        return (f"{report_name} {project_info.get('version')} "
                f"({datetime.now().strftime('%d.%m.%Y')})", components)
    except (ValueError, ConnectionError) as e:
        logger.error(f"Error while generating report: {e}")
        return e, []
