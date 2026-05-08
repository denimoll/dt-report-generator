""" Module for tasks with dependencyGraph """

import copy
import logging

from anytree import Node, RenderTree

logger = logging.getLogger(__name__)


def get_graph(components, depth=3):
    """
    Generate a dependency graph from the components dictionary.

    Args:
        components: A dictionary of components, indexed by ID.
        depth: Max depth of dependencies to walk.

    Returns:
        A formatted string representation of the tree, or 0 if no dependencies found.
    """
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
