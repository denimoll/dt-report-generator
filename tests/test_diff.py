""" Tests for backend.reports.compute_diff """

from backend.reports import compute_diff


def _component(name, version, vulns, group=""):
    return {
        "name": name,
        "version": version,
        "group": group,
        "vulnerabilities": vulns,
    }


def _vuln(vuln_id, severity="high", state="", suppressed=False):
    return {
        "id": vuln_id,
        "link": f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
        "severity": severity,
        "priority": severity,
        "analysis_state": state,
        "is_suppressed": suppressed,
    }


def _data(*components):
    return {"vuln_components": list(components)}


def test_compute_diff_empty_on_both_sides():
    result = compute_diff(_data(), _data())
    assert result == {"added": [], "removed": [], "common": []}


def test_compute_diff_finds_added_vuln():
    a = _data()
    b = _data(_component("libA", "1.0", [_vuln("CVE-2024-0001")]))
    result = compute_diff(a, b)
    assert len(result["added"]) == 1
    assert result["added"][0]["component"] == "libA"
    assert result["added"][0]["vulnerability"] == "CVE-2024-0001"
    assert result["added"][0]["componentVersion"] == "1.0"
    assert result["removed"] == []
    assert result["common"] == []


def test_compute_diff_finds_removed_vuln():
    a = _data(_component("libA", "1.0", [_vuln("CVE-2024-0001")]))
    b = _data()
    result = compute_diff(a, b)
    assert len(result["removed"]) == 1
    assert result["removed"][0]["vulnerability"] == "CVE-2024-0001"
    assert result["added"] == []


def test_compute_diff_finds_common_with_version_change():
    """ Same CVE in both projects but the host component was bumped """
    a = _data(_component("libA", "1.0", [_vuln("CVE-2024-0001")]))
    b = _data(_component("libA", "1.5", [_vuln("CVE-2024-0001")]))
    result = compute_diff(a, b)
    assert len(result["common"]) == 1
    common = result["common"][0]
    assert common["componentVersionA"] == "1.0"
    assert common["componentVersionB"] == "1.5"
    assert common["vulnerability"] == "CVE-2024-0001"
    assert result["added"] == []
    assert result["removed"] == []


def test_compute_diff_distinguishes_groups():
    """ Same component name in different groups are different identities """
    a = _data(_component("util", "1.0", [_vuln("CVE-X")], group="org.foo"))
    b = _data(_component("util", "1.0", [_vuln("CVE-X")], group="org.bar"))
    result = compute_diff(a, b)
    assert len(result["added"]) == 1
    assert len(result["removed"]) == 1
    assert result["common"] == []


def test_compute_diff_mixed_added_removed_common():
    a = _data(
        _component("libA", "1.0", [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")]),
        _component("libB", "2.0", [_vuln("CVE-2024-0003")]),
    )
    b = _data(
        _component("libA", "1.1", [_vuln("CVE-2024-0001")]),  # 0002 fixed
        _component("libC", "3.0", [_vuln("CVE-2024-0009")]),  # new component
    )
    result = compute_diff(a, b)
    added_ids = sorted(e["vulnerability"] for e in result["added"])
    removed_ids = sorted(e["vulnerability"] for e in result["removed"])
    common_ids = sorted(e["vulnerability"] for e in result["common"])
    assert added_ids == ["CVE-2024-0009"]
    assert removed_ids == ["CVE-2024-0002", "CVE-2024-0003"]
    assert common_ids == ["CVE-2024-0001"]


def test_compute_diff_carries_analysis_state_per_side():
    """ Common vulns may have different VEX state in A vs B """
    a = _data(_component("libA", "1.0",
                         [_vuln("CVE-X", state="exploitable", suppressed=False)]))
    b = _data(_component("libA", "1.0",
                         [_vuln("CVE-X", state="false_positive", suppressed=True)]))
    result = compute_diff(a, b)
    assert len(result["common"]) == 1
    c = result["common"][0]
    assert c["analysisStateA"] == "exploitable"
    assert c["analysisStateB"] == "false_positive"
    assert c["isSuppressedA"] is False
    assert c["isSuppressedB"] is True
