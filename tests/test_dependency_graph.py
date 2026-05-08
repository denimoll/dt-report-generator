""" Tests for backend.dependency_graph """

from backend.dependency_graph import compute_graph_levels, get_graph


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
        "graph_level": None,
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


def test_handles_cycle_without_recursion():
    components = {
        "a": _component("libA", is_direct=True, deps=["b"]),
        "b": _component("libB", deps=["a"]),
    }
    out = get_graph(components, depth=10)
    # libA listed exactly once thanks to the visited set; recursion bounded
    assert out.count("libA") == 1
    assert out.count("libB") == 1


def test_skips_missing_dependency_uuid():
    components = {
        "a": _component("libA", is_direct=True, deps=["ghost"]),
    }
    # ghost does not exist in components; traversal should not crash
    out = get_graph(components)
    assert "libA" in out
    assert "ghost" not in out


def test_vulnerable_component_marked():
    components = {
        "a": _component("libA", is_direct=True,
                        vulns=[{"id": "CVE-2024-0001"}],
                        severity="critical"),
    }
    out = get_graph(components)
    assert 'vuln-critical' in out
    assert "[critical vuln]" in out


# compute_graph_levels

def test_compute_graph_levels_marks_direct_deps_as_one():
    components = {
        "a": _component("libA", is_direct=True),
        "b": _component("libB", is_direct=True),
    }
    compute_graph_levels(components)
    assert components["a"]["graph_level"] == 1
    assert components["b"]["graph_level"] == 1


def test_compute_graph_levels_descends():
    components = {
        "a": _component("libA", is_direct=True, deps=["b"]),
        "b": _component("libB", deps=["c"]),
        "c": _component("libC"),
    }
    compute_graph_levels(components, depth=5)
    assert components["a"]["graph_level"] == 1
    assert components["b"]["graph_level"] == 2
    assert components["c"]["graph_level"] == 3


def test_compute_graph_levels_picks_minimum_via_bfs():
    # libC reachable both as a direct dep (level 1) and as a child of libB
    components = {
        "a": _component("libA", is_direct=True, deps=["b"]),
        "b": _component("libB", deps=["c"]),
        "c": _component("libC", is_direct=True),
    }
    compute_graph_levels(components)
    assert components["c"]["graph_level"] == 1


def test_compute_graph_levels_respects_depth():
    components = {
        "a": _component("libA", is_direct=True, deps=["b"]),
        "b": _component("libB", deps=["c"]),
        "c": _component("libC"),
    }
    compute_graph_levels(components, depth=2)
    assert components["a"]["graph_level"] == 1
    assert components["b"]["graph_level"] == 2
    assert components["c"]["graph_level"] is None  # cut by depth


def test_compute_graph_levels_unreachable_stays_none():
    components = {
        "a": _component("libA", is_direct=True),
        "b": _component("libB"),  # not direct, not depended on
    }
    compute_graph_levels(components)
    assert components["a"]["graph_level"] == 1
    assert components["b"]["graph_level"] is None


def test_compute_graph_levels_no_op_without_direct_deps():
    components = {"a": _component("libA")}
    compute_graph_levels(components)
    assert components["a"]["graph_level"] is None


def test_compute_graph_levels_uses_env_default(monkeypatch):
    monkeypatch.setenv("DTRG_GRAPH_DEPTH", "1")
    components = {
        "a": _component("libA", is_direct=True, deps=["b"]),
        "b": _component("libB"),
    }
    compute_graph_levels(components)  # no explicit depth
    assert components["a"]["graph_level"] == 1
    assert components["b"]["graph_level"] is None  # depth=1 stops at direct deps


def test_compute_graph_levels_handles_cycle():
    components = {
        "a": _component("libA", is_direct=True, deps=["b"]),
        "b": _component("libB", deps=["a"]),
    }
    compute_graph_levels(components, depth=10)
    assert components["a"]["graph_level"] == 1
    assert components["b"]["graph_level"] == 2  # not revisited as a's child


def test_compute_graph_levels_skips_missing_uuid():
    components = {
        "a": _component("libA", is_direct=True, deps=["ghost"]),
    }
    compute_graph_levels(components)  # must not crash
    assert components["a"]["graph_level"] == 1
