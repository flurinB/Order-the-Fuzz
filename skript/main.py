import angr
import networkx as nx
from angrutils import plot_cg
from angr.knowledge_plugins.functions import Function
from tqdm import tqdm
import json

"""
Global Variables:
"""

GLOBAL_metric_map = {}  # Maps {addr -> Metric value}
GLOBAL_root_list = []
GLOBAL_project = None  # The main project
GLOBAL_temp_project = None  # The temporary project for each of the emulated analyses from each root
GLOBAL_memory_functions = []
GLOBAL_config = {}


def init_global_variables(path_to_binary, memory_functions):
    global GLOBAL_project, GLOBAL_temp_project, GLOBAL_root_list
    global GLOBAL_visited_map, GLOBAL_metric_map, GLOBAL_memory_functions

    # Load the binary
    GLOBAL_project = angr.Project(path_to_binary, auto_load_libs=False)
    GLOBAL_temp_project = angr.Project(path_to_binary, auto_load_libs=False)

    GLOBAL_memory_functions = memory_functions


def init_global_variables_using_gml(path_to_binary, path_to_gml_file, memory_functions):
    global GLOBAL_project, GLOBAL_temp_project, GLOBAL_root_list
    global GLOBAL_visited_map, GLOBAL_metric_map, GLOBAL_memory_functions

    # Load the binary
    GLOBAL_project = angr.Project(path_to_binary, auto_load_libs=False)

    callgraph = read_graph_from_file(path_to_gml_file)
    GLOBAL_project.kb.functions.callgraph = callgraph

    GLOBAL_memory_functions = memory_functions


"""
Calculating the Metric Values: 
"""


def add_to_visited_map(function):
    global GLOBAL_visited_map
    GLOBAL_visited_map.append(function)


def count_amount_of_functions_in_subgraph(root_addr, covered_functions=[]):
    """
        Counts the amount of functions in the subgraph induced by root_addr
        The parameter "covered_functions" is important for the reordering "Metric",
        after one first fuzzing order has already been established.
        In this case the function is used to count the amount of functions in the subgraph that are
        not covered by root_addr before
    """
    global GLOBAL_project, GLOBAL_memory_functions

    callgraph = GLOBAL_project.kb.functions.callgraph
    visited = set()
    to_visit = [root_addr]
    amount_of_functions = 0

    while to_visit:
        current_func_addr = to_visit.pop()
        if current_func_addr in visited:
            continue
        visited.add(current_func_addr)

        # Skip if the function is a memory operation (not interesting for fuzzing)
        func = GLOBAL_project.kb.functions.get_by_addr(current_func_addr)
        if func.name in GLOBAL_memory_functions:
            continue

        # Skip the function if it is already covered in a previous subtree (FOR REORDERING)
        if current_func_addr in covered_functions:
            continue
        else:
            covered_functions.append(current_func_addr)

        amount_of_functions = amount_of_functions + 1

        # Explore successors
        for succ_addr in callgraph.successors(current_func_addr):
            if succ_addr not in visited:
                to_visit.append(succ_addr)

    return (amount_of_functions, covered_functions)


def count_amount_metrics_for_root_functions():
    global GLOBAL_root_list

    root_list, root_names = GLOBAL_root_list

    memory_calls_hashmap = create_memory_calls_hashmap()
    memory_call_counts = {}
    function_counts = {}

    for root_addr, root_func in root_list:
        amount_of_memory_calls = count_memory_calls_in_call_subtree(root_addr, memory_calls_hashmap)
        amount_of_functions, _ = count_amount_of_functions_in_subgraph(root_addr)
        memory_call_counts[root_func.name] = amount_of_memory_calls
        function_counts[root_func.name] = amount_of_functions

    print("memory calls: ", memory_call_counts)
    print("function_counts: ", function_counts)
    return (memory_call_counts, function_counts)


def create_memory_calls_hashmap():
    """
    Counts how many times each function calls any of the functions in memory_functions.
    Returns a dict { func_addr: count }.
    """
    global GLOBAL_project, GLOBAL_memory_functions
    callgraph = GLOBAL_project.kb.functions.callgraph
    call_counts = {}

    for func_addr in callgraph.nodes():
        func = GLOBAL_project.kb.functions.get_by_addr(func_addr)
        if not func:
            continue

        call_counts[func_addr] = 0
        for succ_addr in callgraph.successors(func_addr):
            succ_func = GLOBAL_project.kb.functions.get_by_addr(succ_addr)

            if succ_func and succ_func.name in GLOBAL_memory_functions:
                call_counts[func_addr] += 1

    return call_counts


def count_memory_calls_in_call_subtree(root_addr, memory_calls_hashmap):
    """
    Counts the number of memory function calls reachable from root_addr in the callgraph.
    """
    global GLOBAL_project, GLOBAL_memory_functions

    callgraph = GLOBAL_project.kb.functions.callgraph
    visited = set()
    to_visit = [root_addr]
    amount_of_memory_operations = 0

    while to_visit:
        current_func_addr = to_visit.pop()
        if current_func_addr in visited:
            continue
        visited.add(current_func_addr)

        # Skip if the function itself is a memory operation
        func = GLOBAL_project.kb.functions.get_by_addr(current_func_addr)
        if func.name in GLOBAL_memory_functions:
            continue

        amount_of_memory_operations += memory_calls_hashmap[current_func_addr]

        # Explore successors
        for succ_addr in callgraph.successors(current_func_addr):
            if succ_addr not in visited:
                to_visit.append(succ_addr)

    return amount_of_memory_operations


def get_normalized_values(map):
    """
    Converts the values of a map to normalized values (max element = 1)
    """
    if not map:
        return {}

    max_value = max(map.values())

    if max_value == 0:
        # Avoid division by zero: return the same map with all zeros
        return {k: 0 for k in map}

    normalized_map = {k: v / max_value for k, v in map.items()}
    return normalized_map


def calculate_metric_values_for_choosing_entry_point_order(alpha, beta):
    global GLOBAL_metric_map, GLOBAL_root_list
    memory_call_counts, function_counts = count_amount_metrics_for_root_functions()

    root_list, root_names = GLOBAL_root_list

    # Probabilistic values make more sense for the metric values
    memory_call_counts = get_normalized_values(memory_call_counts)
    function_counts = get_normalized_values(function_counts)

    for root_addr, root_func in root_list:
        GLOBAL_metric_map[root_func] = alpha * memory_call_counts[root_func.name] + beta * function_counts[
            root_func.name]

    return


def reorder(order):
    """
        Reorders a given fuzzing-order according to how many functions have not yet been covered
        by the subtrees of the graph induced by the root functions prior in the order
    """

    remaining_functions_metric = {}
    covered_functions = []
    for root_addr in order:
        amount_of_remaining_functions, covered_functions = count_amount_of_functions_in_subgraph(root_addr,
                                                                                                 covered_functions)
        remaining_functions_metric[root_addr] = amount_of_remaining_functions

    # Sort the functions in descending order of not yet visited functions
    new_order = dict(sorted(remaining_functions_metric.items(), key=lambda item: item[1], reverse=True))
    new_order = list(new_order)

    return new_order


def reorder_n_times(order, n):
    """
        Reorders a given fuzzing-order either until reordering does not change the order
        or until it has been reordered n times (infinite if n = -1)
    """
    new_order = []
    i = 0

    while new_order != order:
        # If it has been reordered n times:
        if n != -1 and i >= n:
            break

        # If it is not the first iteration, reallocate the order:
        if i != 0:
            order = new_order

        new_order = reorder(order)
        i += 1

        print("reordered, old order:", order, "new order:", new_order)

    return new_order if new_order else order


"""
Building the Call Graph: 
"""


def analyze_program(cfg_fast):
    """
    Analyzes the program by processing root functions and adjusting the call graph as needed.
    """
    global GLOBAL_root_list, GLOBAL_project, GLOBAL_temp_project, GLOBAL_memory_functions

    root_list, root_names = GLOBAL_root_list

    # Progress bar initialization:
    with tqdm(total=len(root_list), desc="Processing Root Functions") as pbar:

        for func_addr, func in root_list:
            # Progress bar updating:
            pbar.set_description(f"Analyzing {hex(func_addr)}")
            pbar.update()

            # Create a blank state and build an emulated CFG starting from this function
            start_state = GLOBAL_temp_project.factory.blank_state(addr=func_addr)
            temp_cfg_emu = GLOBAL_temp_project.analyses.CFGEmulated(
                fail_fast=True, starts=[func_addr], initial_state=start_state
            )

            temp_cfg_edges_by_address = []
            for src_node, dst_node, edge_data in temp_cfg_emu.graph.edges(data=True):
                jumpkind = edge_data.get("jumpkind", None)
                # Only keep real call instructions, NO RETURNS!
                if jumpkind != "Ijk_Call":
                    continue

                # Convert to (src_func_addr, dst_func_addr)
                item = edge_to_function_address(GLOBAL_temp_project, (src_node, dst_node))
                if not item:
                    continue

                src_addr, dst_addr = item
                dst_func = GLOBAL_temp_project.kb.functions.function(dst_addr)
                if not dst_func:
                    # If we can't identify the destination function, skip
                    continue

                temp_cfg_edges_by_address.append(item)

            # Build a set of edges by address for the existing CFGFast
            cfg_fast_edges_by_address = [
                edge_to_function_address(GLOBAL_project, edge)
                for edge in cfg_fast.graph.edges
            ]
            cfg_fast_edges_by_address = set(e for e in cfg_fast_edges_by_address if e)

            # Compare: if temp_cfg_emu found new call edges not in cfg_fast, add them
            difference_result = [
                item for item in temp_cfg_edges_by_address
                if item not in cfg_fast_edges_by_address
            ]
            for item in difference_result:
                if item is None or len(item) < 2:
                    continue
                add_missing_call_edge(
                    item[0], item[1],
                    root_node=func.name,
                    difference_result=difference_result
                )

    callgraph = GLOBAL_project.kb.functions.callgraph

    # Filtering the unnecessary functions out of the Call Graph
    _ = filter_functions(
        GLOBAL_project.kb.functions.values(),
        callgraph,
        remove_sub_n=GLOBAL_config.get("remove_sub_n_functions", False)
    )

    remove_self_loops(callgraph)

    # Get new root functions
    update_rootlist()

    return


def edge_to_function_address(project, edge):
    """
    Maps one edge of the graph (src_node, dst_node) to function addresses, focusing on the call graph.
    Returns (src_func.addr, dst_func.addr) or None if unknown.
    USED FOR BOTH THE TMP PROJECT (EMULATED CFG) AS WELL AS THE MAIN PROJECT
    """

    src_node, dst_node = edge
    src_addr = src_node.addr
    dst_addr = dst_node.addr

    # "floor" the addresses to the functions they belong to
    src_func = project.kb.functions.floor_func(src_addr)
    dst_func = project.kb.functions.floor_func(dst_addr)

    # If a function is missing, skip
    if src_func is None:
        print("Source function is unknown: ", hex(src_addr), "\nSkipping edge")
        return None
    if dst_func is None:
        print("Destination function is unknown: ", hex(dst_addr), "\nSkipping edge")
        return None

    return (src_func.addr, dst_func.addr)


def add_missing_call_edge(src_addr, dst_addr, root_node=None, difference_result=None):
    """
    Adds a missing edge between two functions in the call graph, if it does not exist yet.
    ONLY USED FOR THE MAIN CG IN THE MAIN PROJECT
    """
    global GLOBAL_project
    if isinstance(src_addr, str):
        src_addr = int(src_addr, 16)
    if isinstance(dst_addr, str):
        dst_addr = int(dst_addr, 16)

    src_func = GLOBAL_project.kb.functions.function(addr=src_addr)
    if src_func is None:
        print("Source function is unknown: ", hex(src_addr), "\nSkipping edge")
        return

    dst_func = GLOBAL_project.kb.functions.function(addr=dst_addr)
    if dst_func is None:
        print("Destination function is unknown: ", hex(dst_addr), "\nSkipping edge")
        return

    callgraph = GLOBAL_project.kb.functions.callgraph
    if not callgraph.has_edge(src_func.addr, dst_func.addr):
        callgraph.add_edge(src_func.addr, dst_func.addr)
        print(
            f"Added edge from {hex(src_func.addr)}, {src_func.name} "
            f"to {hex(dst_func.addr)}, {dst_func.name}, root node: {root_node}, "
            f"difference result = {difference_result}"
        )


def update_rootlist():
    """
    Updates the global root list with root functions and their names.
    """
    global GLOBAL_root_list, GLOBAL_project
    callgraph = GLOBAL_project.kb.functions.callgraph
    root_list = []
    root_names = []

    for func_addr, func in GLOBAL_project.kb.functions.items():
        if not callgraph.has_node(func_addr):
            continue

        preds = list(callgraph.predecessors(func_addr))
        if not preds:  # no predecessors => root
            root_names.append(func.name)
            root_list.append((func_addr, func))

    GLOBAL_root_list = (root_list, root_names)


def remove_node_from_cg(callgraph, func_addr):
    """
    Removes a node from the call graph if it exists.
    """
    if callgraph.has_node(func_addr):
        callgraph.remove_node(func_addr)
        print(f"Removed function {hex(func_addr)} from callgraph")
    else:
        print(f"Function {hex(func_addr)} is not in callgraph.")


def filter_functions(functions, callgraph, remove_sub_n=False):
    """
    Removes from the callgraph any function that is PLT, syscall, simprocedure, etc.,
    or (optionally) named "sub_<something>" if remove_sub_n is True,
    unless its name or address is within the GLOBAL_memory_functions list.

    Returns the list of removed functions.
    """
    global GLOBAL_memory_functions

    exceptions = GLOBAL_memory_functions
    to_remove = []

    for f in functions:
        # 1) Already removed or invalid
        if not callgraph.has_node(f.addr):
            continue

        # 2) If function is in the memory_functions list, skip it
        if (f.name in exceptions) or (f.addr in exceptions):
            continue

        # 3) If remove_sub_n is True and the function name starts with 'sub_', remove it
        #    For example: sub_401000, sub_1337ABC, etc.
        if remove_sub_n and f.name.startswith("sub_"):
            to_remove.append(f)
            continue

        # 4) If function is PLT, syscall, or simprocedure => remove
        if f.is_syscall or f.is_plt or f.is_simprocedure:
            to_remove.append(f)

    for function in to_remove:
        remove_node_from_cg(callgraph, function.addr)

    return to_remove


def remove_self_loops(callgraph):
    """
    Removes self-loop edges from the callgraph.
    """
    self_loops = list(nx.selfloop_edges(callgraph))
    for src, dst in self_loops:
        callgraph.remove_edge(src, dst)
        print(f"Removed self-loop at function {hex(src)}")
    return


def update_progress_bar(progress_bar, task_description):
    """
    Updates the TQDM progress bar with a new description.
    """
    progress_bar.set_description(task_description)
    progress_bar.update()


"""
File Storage Handling: 
"""


def save_graph_to_file(graph, path_to_file):
    """
    Saves the NetworkX graph to a file (GML).
    """
    nx.write_gml(graph, path_to_file)


def read_graph_from_file(path_to_file):
    """
    Reads a GML file into a NetworkX graph, converting node labels from hex strings to int.
    """
    graph = nx.read_gml(path_to_file)
    mapping = {}
    for node in graph.nodes():
        if isinstance(node, str) and node.startswith("0x"):
            mapping[node] = int(node, 16)

    if mapping:
        nx.relabel_nodes(graph, mapping, copy=False)
    return graph


def load_config(config_file):
    """
    Loads a config JSON file.
    """
    with open(config_file, 'r') as file:
        return json.load(file)


def save_fuzzing_order_to_file(sorted_function_map, output_file):
    """
    Saves the ordered list of functions to fuzz into a file.

    :param sorted_function_map: A dictionary of functions sorted by their metric values.
    :param output_file: Path to the output file.
    """
    with open(output_file, 'w') as file:
        file.write("Order in which to fuzz the program:\n\n")
        for index, (func, value) in enumerate(sorted_function_map.items(), start=1):
            file.write(f"{index}. Function: {func.name} at {hex(func.addr)} - Metric Value: {value:.4f}\n")
    print(f"Fuzzing order saved to {output_file}")


if __name__ == '__main__':
    GLOBAL_config = load_config("config.json")  # <--- Store in global config

    use_gml_file = GLOBAL_config.get("use_gml_file", False)
    path_to_binary = GLOBAL_config.get("path_to_binary", "")
    path_to_gml_file = GLOBAL_config.get("path_to_gml_file", "")
    # List of recognized memory operations (Example: ["malloc", "calloc", "printf", "memcpy"])
    memory_functions = GLOBAL_config.get("memory_functions", [])
    output_plot_path = GLOBAL_config.get("output_plot_path", "")
    output_graph_path = GLOBAL_config.get("output_graph_path", "")
    # Amount of times the order gets reordered, -1 = as many as possible
    reorder_amount = GLOBAL_config.get("reorder_amount", -1)
    # Weight of the metric 1: amount of memory calls within subtree
    memory_call_count_weight = GLOBAL_config.get("memory_call_count_weight", 1)
    # Weight of the metric 2: amount of functions within subtree
    function_count_weight = GLOBAL_config.get("function_count_weight", 1)

    if use_gml_file:
        # Load the graph from a .gml file
        print(f"Loading call graph from {path_to_gml_file}")
        init_global_variables_using_gml(path_to_binary, path_to_gml_file, memory_functions)

        # IMPORTANT: analyse the project for a complete knowledge base:
        _ = GLOBAL_project.analyses.CFGFast()

        # Update root functions from the loaded graph
        update_rootlist()
        root_list, root_names = GLOBAL_root_list
        print("Root functions loaded from .gml file:", root_names)

    else:
        # Normal binary analysis
        init_global_variables(path_to_binary, memory_functions)

        # Generate CFG & build knowledge base
        cfg_fast = GLOBAL_project.analyses.CFGFast()

        # Find root functions
        update_rootlist()
        root_list, root_names = GLOBAL_root_list
        print("Root functions before analysis:", root_names)

        # Analyze the program (adding missing edges, etc.)
        analyze_program(cfg_fast)

        # Show updated root list if it changed
        update_rootlist()
        root_list, root_names = GLOBAL_root_list
        print("Root functions after analysis:", root_names)

        # Save final callgraph to file
        save_graph_to_file(GLOBAL_project.kb.functions.callgraph, output_graph_path)

        # Plot and output results
        plot_cg(GLOBAL_project.kb, output_plot_path, format="png")

    # Calculate metrics and fuzzing order
    calculate_metric_values_for_choosing_entry_point_order(memory_call_count_weight, function_count_weight)
    sorted_by_value_ascending = dict(sorted(GLOBAL_metric_map.items(), key=lambda item: item[1], reverse=True))

    # Retrieve the raw addresses of the root functions in the metric map
    root_list, _ = GLOBAL_root_list
    keys_list = [f.addr for f in GLOBAL_metric_map.keys()]

    # Reorder the final fuzzing list
    final_order = reorder_n_times(keys_list, reorder_amount)

    # Save the fuzzing order to file
    save_fuzzing_order_to_file(sorted_by_value_ascending, "fuzzing_order.txt")
