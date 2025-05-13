""" Module for tasks with dependencyGraph """

import copy
import logging

from PrettyPrint import PrettyPrintTree

logger = logging.getLogger(__name__)


class Tree:
    """ Classic tree class """

    def __init__(self, value):
        """ Initialize a Tree node """
        self.val = value
        self.children = []

    def add_child(self, child):
        """ Add a child node to the current node """
        self.children.append(child)
        return child


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
    # create Pretty Tree
    pt = PrettyPrintTree(
        lambda x: x.children,
        lambda x: x.val,
        color='',
        orientation=PrettyPrintTree.Horizontal,
        return_instead_of_print=True
    )
    tree = Tree("  Application  ")

    def update_direct_dependencies(dependencies, depth):
        """ Recursively expand all nested dependencies """
        logger.debug(f"Expanding dependencies at depth={depth}")
        deps_deps = []
        copy_dependencies = copy.deepcopy(dependencies)

        for num, dependency in enumerate(copy_dependencies):
            for dep in dependency.get("dependencies"):
                dep_value = copy.deepcopy(components.get(dep))
                deps_deps.append(dep_value)
                dependencies[num]["dependencies"] = update_direct_dependencies(
                    copy.deepcopy(deps_deps), depth-1) if depth and deps_deps else []
            deps_deps = []
        return dependencies

    def update_tree(tree, dependencies):
        """ Recursively add dependencies to the tree """
        for dependency in dependencies:
            if dependency.get("vulnerabilities"):
                node_name = f"  [VULNERABLE] [{dependency.get('severity')}]  \n  "
                node_name += f"{dependency.get('name')}@{dependency.get('version')}  \n  "
                node_name += f"Last version {dependency.get('last_version')}  "
            else:
                node_name = f"  {dependency.get('name')}@{dependency.get('version')}  "
            d = tree.add_child(Tree(node_name))
            d_dependencies = dependency.get("dependencies")
            if d_dependencies:
                d = update_tree(d, d_dependencies)
        return tree

    direct_dependencies = [v for v in components.values() if v.get("is_direct_dependency")]
    if not direct_dependencies:
        logger.info("No direct dependencies found")
        return 0
    logger.info(f"Found {len(direct_dependencies)} direct dependencies")
    tree = update_tree(tree,
        update_direct_dependencies(copy.deepcopy(direct_dependencies), depth-1))
    return pt(tree)
