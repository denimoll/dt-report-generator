""" Tests for backend.dependency_graph """

from backend.dependency_graph import get_graph


def _component(name, *, is_direct=False, deps=None, vulns=None, severity=""):
    """ Build a components-dict entry with the shape create_report produces """
    return {
        "name": name,
        "version": "1.0",
        "group": "",
        "last_version": "1.0",
        "is_direct_dependency": is_direct,
        "dependencies": deps or [],
        "vulnerabilities": vulns or [],
        "severity": severity,
        "severity_level": 0,
        "graph_level": 0,
    }


def test_no_direct_dependencies_returns_zero():
    components = {"a": _component("libA", is_direct=False)}
    assert get_graph(components) == 0


def test_renders_single_direct_dep():
    components = {"a": _component("libA", is_direct=True)}
    out = get_graph(components)
    assert "libA" in out
    assert "Application" in out


def test_renders_nested_dep():
    components = {
        "a": _component("libA", is_direct=True, deps=["b"]),
        "b": _component("libB"),
    }
    out = get_graph(components)
    assert "libA" in out
    assert "libB" in out
    # libB rendered after libA in the tree output
    assert out.index("libA") < out.index("libB")


def test_depth_one_drops_children():
    components = {
        "a": _component("libA", is_direct=True, deps=["b"]),
        "b": _component("libB"),
    }
    out = get_graph(components, depth=1)
    assert "libA" in out
    assert "libB" not in out


def test_vulnerable_component_marked():
    components = {
        "a": _component("libA", is_direct=True,
                        vulns=[{"id": "CVE-2024-0001"}],
                        severity="critical"),
    }
    out = get_graph(components)
    assert 'vuln-critical' in out
    assert "[critical vuln]" in out
