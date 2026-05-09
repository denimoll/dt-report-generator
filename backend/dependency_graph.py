""" Module for tasks with dependencyGraph """

import copy
import logging

from anytree import Node, RenderTree

from backend.param_validators import graph_depth

logger = logging.getLogger(__name__)


def compute_graph_levels(components, depth=None):
    """
    Walk the dependency graph and write graph_level back into each component.

    Direct dependencies get level 1. Their children get level 2, and so on.
    Components that are not reached (no path from a direct dep, or beyond
    the depth limit) keep their pre-existing graph_level (typically None).
    Each component is visited once: the shallowest path wins.

    Args:
        components: A dictionary of components, indexed by ID. Mutated in place.
        depth: Max depth to walk. Defaults to DTRG_GRAPH_DEPTH (env-controlled).
    """
    if depth is None:
        depth = graph_depth()

    direct_uuids = {k for k, v in components.items() if v.get("is_direct_dependency")}
    if not direct_uuids:
        return

    visited = set(direct_uuids)
    for uuid in direct_uuids:
        components[uuid]["graph_level"] = 1

    frontier = [(uuid, 1) for uuid in direct_uuids]
    while frontier:
        next_frontier = []
        for uuid, level in frontier:
            if level >= depth:
                continue
            for child in components[uuid].get("dependencies") or []:
                if child in visited or child not in components:
                    continue
                visited.add(child)
                components[child]["graph_level"] = level + 1
                next_frontier.append((child, level + 1))
        frontier = next_frontier


def get_graph(components, depth=None):
    """
    Generate a dependency graph from the components dictionary.

    Args:
        components: A dictionary of components, indexed by ID.
        depth: Max depth of dependencies to walk. Defaults to DTRG_GRAPH_DEPTH.

    Returns:
        A formatted string representation of the tree, or 0 if no dependencies found.
    """
    if depth is None:
        depth = graph_depth()
    logger.debug(f"Generating graph with depth={depth}")

    # create Tree root
    tree = Node("Application")

    def update_direct_dependencies(dependencies, depth, visited=None):
        """ Recursively expand all nested dependencies """
        logger.debug(f"Expanding dependencies at depth={depth}")
        if visited is None:
            visited = set()
        copy_dependencies = copy.deepcopy(dependencies)

        for num, dependency in enumerate(copy_dependencies):
            deps_deps = []
            for dep in dependency.get("dependencies") or []:
                if dep in visited:
                    continue
                visited.add(dep)
                dep_value = copy.deepcopy(components.get(dep))
                if dep_value is None:
                    continue
                deps_deps.append(dep_value)
            if deps_deps and depth:
                dependencies[num]["dependencies"] = update_direct_dependencies(
                    copy.deepcopy(deps_deps), depth-1, visited)
            else:
                dependencies[num]["dependencies"] = []
        return dependencies

    def update_tree(tree, dependencies):
        """ Recursively add dependencies to the tree """
        for dependency in dependencies:
            if dependency.get("vulnerabilities"):
                severity = dependency.get("severity")
                node_name = (f'<span class="vuln vuln-{severity.lower()}">\
[{severity} vuln] \
{dependency.get("name")}@{dependency.get("version")} (last: {dependency.get("last_version")})\
</span>')
            else:
                node_name = f'<span class="pkg">\
{dependency.get("name")}@{dependency.get("version")}</span>'

            d = Node(node_name, parent=tree)

            d_dependencies = dependency.get("dependencies")
            if d_dependencies:
                update_tree(d, d_dependencies)

        return tree

    direct_uuids = {k for k, v in components.items() if v.get("is_direct_dependency")}

    if not direct_uuids:
        logger.info("No direct dependencies found")
        return 0

    direct_dependencies = [components[k] for k in direct_uuids]
    logger.info(f"Found {len(direct_dependencies)} direct dependencies")

    tree = update_tree(
        tree,
        update_direct_dependencies(copy.deepcopy(direct_dependencies), depth-1,
                                   visited=set(direct_uuids))
    )

    # Render tree to string
    lines = []
    for pre, _, node in RenderTree(tree):
        lines.append(f"{pre}{node.name}")

    return "\n".join(lines)
