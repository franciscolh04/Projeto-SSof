import ast
import json
import os
import sys

OUTPUT_DIR = "./output"
DEBUG_DIR = "./debug"
DEBUG = True
DEBUG_FILE = None

def debug_print(message):
    """Print debug message to file if DEBUG is enabled"""
    if DEBUG and DEBUG_FILE:
        DEBUG_FILE.write(message + "\n")
        DEBUG_FILE.flush()

class VulnerabilityFinder(ast.NodeVisitor):
    def __init__(self, patterns):
        self.patterns = patterns
        for i, p in enumerate(self.patterns):
            p['_index'] = i

        self.tainted_vars = {}
        self.vulnerabilities = []
        self.assigned_vars = set()

        self.vuln_family_order = []

        self.sources_map = {}
        self.sinks_map = {}
        self.sanitizers_map = {}

        self.vulnerability_count = {}

        self._build_patterns_maps()

        if DEBUG:
            debug_print("[DEBUG] VulnerabilityFinder initialized with {} patterns".format(len(patterns)))
            debug_print("[DEBUG] Sources: {}".format(list(self.sources_map.keys())))
            debug_print("[DEBUG] Sinks: {}".format(list(self.sinks_map.keys())))
            debug_print("[DEBUG] Sanitizers: {}".format(list(self.sanitizers_map.keys())))

    def _build_patterns_maps(self):
        if DEBUG:
            debug_print("[DEBUG] Building pattern maps...")

        for pattern in self.patterns:
            if DEBUG:
                debug_print("[DEBUG]   Pattern: {}".format(pattern.get('vulnerability')))

            # Build sources map
            for source_name in pattern.get("sources", []):
                if source_name not in self.sources_map:
                    self.sources_map[source_name] = []
                self.sources_map[source_name].append(pattern)
                if DEBUG:
                    debug_print("[DEBUG]     Added source: {}".format(source_name))

            # Build sanitizers map
            for sanitizer_name in pattern.get("sanitizers", []):
                if sanitizer_name not in self.sanitizers_map:
                    self.sanitizers_map[sanitizer_name] = []
                self.sanitizers_map[sanitizer_name].append(pattern)
                if DEBUG:
                    debug_print("[DEBUG]     Added sanitizer: {}".format(sanitizer_name))

            # Build sinks map
            for sink_name in pattern.get("sinks", []):
                if sink_name not in self.sinks_map:
                    self.sinks_map[sink_name] = []
                self.sinks_map[sink_name].append(pattern)
                if DEBUG:
                    debug_print("[DEBUG]     Added sink: {}".format(sink_name))

    def _extract_node_name(self, node):
        result = None
        if isinstance(node, ast.Name): # Variable or function name
            result = node.id
        elif isinstance(node, ast.Call): # Function call
            result = self._extract_node_name(node.func)
        elif isinstance(node, ast.Attribute): # Attribute access
            value_name = self._extract_node_name(node.value)
            if value_name:
                result = f"{value_name}.{node.attr}"
        elif isinstance(node, ast.Subscript): # Subscript access
            result = self._extract_node_name(node.value)

        if DEBUG and result:
            debug_print("[DEBUG]     Extracted node name: {} (type: {})".format(result, type(node).__name__))

        return result

    def _sort_flows(self, flows):
        if DEBUG:
            debug_print("[DEBUG]   Sorting {} flows...".format(len(flows)))

        def sort_key(flow):
            vuln_name = flow['pattern']['vulnerability']
            # If the vulnerability family is known, get its index
            if vuln_name in self.vuln_family_order:
                history_index = self.vuln_family_order.index(vuln_name)
            else:
                # If it's new, it goes to the end of the history (but before other new ones with a higher index)
                history_index = len(self.vuln_family_order)

            # Use the index in the JSON file as a tiebreaker
            json_index = flow['pattern']['_index']

            if DEBUG:
                debug_print("[DEBUG]     Flow '{}' -> sort_key=({}, {})".format(vuln_name, history_index, json_index))

            return (history_index, json_index)

        sorted_flows = sorted(flows, key=sort_key)

        if DEBUG:
            debug_print("[DEBUG]   Flows sorted")

        return sorted_flows

    def _get_flows_from_node(self, node):
        flows = []

        if isinstance(node, ast.Name):
            var_name = node.id

            if DEBUG:
                debug_print("[DEBUG]     Getting flows from variable: {}".format(var_name))

            # If the variable is tainted, copy all its flows
            if var_name in self.tainted_vars:
                if DEBUG:
                    debug_print("[DEBUG]       Variable is tainted with {} flow(s)".format(len(self.tainted_vars[var_name])))
                for flow in self.tainted_vars[var_name]:
                    flows.append(flow.copy())

            # Check if the variable is a Source itself
            if var_name in self.sources_map:
                if DEBUG:
                    debug_print("[DEBUG]       Variable is a source")
                for pattern in self.sources_map[var_name]:
                    flows.append({
                        "pattern": pattern,
                        "source": [var_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    })

            # Check if it is a Non-Instantiated Variable (Implicit Source)
            if var_name not in self.assigned_vars and var_name not in self.sources_map:
                if DEBUG:
                    debug_print("[DEBUG]       Variable is implicit source (not assigned)")
                # Add as source for all patterns
                for pattern in self.patterns:
                    flows.append({
                        "pattern": pattern,
                        "source": [var_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    })

        elif isinstance(node, ast.Call):
            func_name = self._extract_node_name(node.func)
            if DEBUG:
                debug_print("[DEBUG]     Getting flows from Call: {}".format(func_name))

            # Collect flows from arguments
            arg_flows = []
            for arg in node.args:
                arg_flows.extend(self._get_flows_from_node(arg))
            
            # Apply sanitization if this function is a sanitizer
            if func_name in self.sanitizers_map:
                if DEBUG:
                    debug_print("[DEBUG]       Function is a sanitizer")
                sanitized_flows = []
                for flow in arg_flows:
                    new_flow = flow.copy()
                    # Ensure sanitizers list is a new list
                    current_sanitizers = list(new_flow.get("sanitizers", []))
                    
                    if func_name in new_flow["pattern"].get("sanitizers", []):
                        current_sanitizers.append([func_name, node.lineno])
                    
                    new_flow["sanitizers"] = current_sanitizers
                    sanitized_flows.append(new_flow)
                arg_flows = sanitized_flows

            # Check if this function call is a Source
            if func_name in self.sources_map:
                if DEBUG:
                    debug_print("[DEBUG]       Function is a source")
                for pattern in self.sources_map[func_name]:
                    arg_flows.append({
                        "pattern": pattern,
                        "source": [func_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    })
            
            flows.extend(arg_flows)

        elif isinstance(node, ast.BinOp):
            if DEBUG:
                debug_print("[DEBUG]     Getting flows from BinOp")
            flows.extend(self._get_flows_from_node(node.left))
            flows.extend(self._get_flows_from_node(node.right))

        elif isinstance(node, ast.UnaryOp):
            if DEBUG:
                debug_print("[DEBUG]     Getting flows from UnaryOp")
            flows.extend(self._get_flows_from_node(node.operand))

        elif isinstance(node, ast.Call):
            if DEBUG:
                debug_print("[DEBUG]     Getting flows from Call with {} args".format(len(node.args)))
            for arg in node.args:
                flows.extend(self._get_flows_from_node(arg))

        elif isinstance(node, ast.Attribute):
            if DEBUG:
                debug_print("[DEBUG]     Getting flows from Attribute")
            flows.extend(self._get_flows_from_node(node.value)) 

        elif isinstance(node, ast.Subscript):
            if DEBUG:
                debug_print("[DEBUG]     Getting flows from Subscript")
            flows.extend(self._get_flows_from_node(node.value))

        if DEBUG:
            debug_print("[DEBUG]     Total flows collected: {}".format(len(flows)))

        return flows

    def _report_vulnerability(self, sink_name, sink_lineno, flow):
        pattern = flow['pattern']

        # Keep track of vulnerability family order
        vuln_name_base = pattern['vulnerability']
        if vuln_name_base not in self.vuln_family_order:
            self.vuln_family_order.append(vuln_name_base)

        source_id = flow['source']

        if DEBUG:
            debug_print("[DEBUG] Reporting vulnerability: {} at line {}".format(vuln_name_base, sink_lineno))
            debug_print("[DEBUG]   Source: {}".format(source_id))
            debug_print("[DEBUG]   Sink: {}".format(sink_name))
            debug_print("[DEBUG]   Sanitizers: {}".format(flow['sanitizers']))
            debug_print("[DEBUG]   Implicit: {}".format(flow['implicit']))

        # Check if this vulnerability has already been reported
        for vuln in self.vulnerabilities:
            if (vuln['vulnerability'].startswith(vuln_name_base) and 
                vuln['source'] == source_id and 
                vuln['sink'] == [sink_name, sink_lineno]):

                if DEBUG:
                    debug_print("[DEBUG]   Vulnerability already reported, checking for new flow...")

                # Add new flow if it's not already present
                new_flow_entry = [
                    "implicit" if flow['implicit'] else "explicit",
                    list(flow['sanitizers']) # Ensure we store a copy
                ]
                if new_flow_entry not in vuln['flows']:
                    vuln['flows'].append(new_flow_entry)
                    if DEBUG:
                        debug_print("[DEBUG]   Added new flow to existing vulnerability: {}".format(new_flow_entry))
                else:
                    if DEBUG:
                        debug_print("[DEBUG]   Flow already exists, skipping: {}".format(new_flow_entry))
                return

        # If not found, create a new entry
        if vuln_name_base not in self.vulnerability_count:
            self.vulnerability_count[vuln_name_base] = 0
        self.vulnerability_count[vuln_name_base] += 1

        vuln_id = f"{vuln_name_base}_{self.vulnerability_count[vuln_name_base]}"

        if DEBUG:
            debug_print("[DEBUG]   Creating new vulnerability: {}".format(vuln_id))

        # Create new vulnerability report entry and add to the list
        vulnerability_report = {
            "vulnerability": vuln_id,
            "source": flow['source'],
            "sink": [sink_name, sink_lineno],
            "flows": [
                [
                    "implicit" if flow['implicit'] else "explicit",
                    list(flow['sanitizers']) # Ensure we store a copy
                ]
            ]
        }
        self.vulnerabilities.append(vulnerability_report)

        if DEBUG:
            debug_print("[DEBUG]   Total vulnerabilities: {}".format(len(self.vulnerabilities)))

    def visit_Assign(self, node):
        # Visit the value to catch any nested assignments
        self.generic_visit(node)

        # Get Target and Value Names
        if not isinstance(node.targets[0], ast.Name):
            return
        target_name = node.targets[0].id
        value_name = self._extract_node_name(node.value)

        if DEBUG:
            debug_print("[DEBUG] Assignment at line {}: {} = {}".format(node.lineno, target_name, value_name))

        # Mark the variable as assigned to avoid implicit source detection
        self.assigned_vars.add(target_name)

        if DEBUG:
            debug_print("[DEBUG]   Getting incoming flows from value...")

        # Get flows from value (handles sanitizers and sources recursively)
        collected_flows = self._get_flows_from_node(node.value)

        if DEBUG:
            debug_print("[DEBUG]   Incoming flows: {}".format(len(collected_flows)))

        # Assign the collected flows to the target variable
        if collected_flows:
            self.tainted_vars[target_name] = collected_flows
            if DEBUG:
                debug_print("[DEBUG]   Variable '{}' is now tainted with {} flow(s)".format(target_name, len(collected_flows)))

            # If the target variable is a sink
            if target_name in self.sinks_map:
                if DEBUG:
                    debug_print("[DEBUG]   Variable '{}' is a sink".format(target_name))

                sorted_flows = self._sort_flows(collected_flows)
                for flow in sorted_flows:
                    # Check each flow for matching patterns
                    if target_name in flow['pattern'].get('sinks', []):
                        self._report_vulnerability(target_name, node.lineno, flow)

        # If no tainted flows, remove the variable from tainted vars
        elif target_name in self.tainted_vars:
            if DEBUG:
                debug_print("[DEBUG]   Variable '{}' is no longer tainted".format(target_name))
            del self.tainted_vars[target_name]

    def visit_Call(self, node):
        # Visit the call arguments to catch any nested calls
        self.generic_visit(node)

        # Get the function name being called
        func_name = self._extract_node_name(node.func)

        if DEBUG:
            debug_print("[DEBUG] Function call at line {}: {}".format(node.lineno, func_name))

        # Check if the function called is a sink
        if func_name in self.sinks_map:
            if DEBUG:
                debug_print("[DEBUG]   Function '{}' is a sink".format(func_name))
            all_flows = []

            # Collect flows from all arguments
            if DEBUG:
                debug_print("[DEBUG]   Collecting flows from {} arguments".format(len(node.args)))

            for arg in node.args:
                all_flows.extend(self._get_flows_from_node(arg))

            if DEBUG:
                debug_print("[DEBUG]   Total flows collected from arguments: {}".format(len(all_flows)))

            if not all_flows:
                if DEBUG:
                    debug_print("[DEBUG]   No flows found, skipping sink check")
                return

            # Check each flow for matching patterns
            sorted_flows = self._sort_flows(all_flows)

            if DEBUG:
                debug_print("[DEBUG]   Checking {} flows against patterns".format(len(sorted_flows)))

            for flow in sorted_flows:
                pattern = flow["pattern"]
                if DEBUG:
                    debug_print("[DEBUG]     Checking pattern: {}".format(pattern.get('vulnerability')))

                if func_name in pattern.get("sinks", []):
                    if DEBUG:
                        debug_print("[DEBUG]     Pattern matches! Reporting vulnerability...")
                    self._report_vulnerability(func_name, node.lineno, flow)
                else:
                    if DEBUG:
                        debug_print("[DEBUG]     Pattern does not match sink")

    def visit_Expr(self, node):
        # Visit expressions to catch any nested calls or assignments
        self.generic_visit(node)


def parse_slice_file(slice_file_path):
    # Check if the file exists
    if not os.path.exists(slice_file_path):
        print("Error: File Not Found:", slice_file_path)
        sys.exit(1)

    if DEBUG:
        debug_print("[DEBUG] Reading slice file: {}".format(slice_file_path))

    try:
        # Read and parse the slice file
        with open(slice_file_path, "r") as f:
            slice_code = f.read()

        if DEBUG:
            debug_print("[DEBUG] Slice file read successfully ({} bytes)".format(len(slice_code)))
            debug_print("[DEBUG] Parsing slice file...")

        slice_ast = ast.parse(slice_code)

        if DEBUG:
            debug_print("[DEBUG] Slice file parsed successfully")
    except SyntaxError as e:
        print("Error: Syntax Error in Slice File:", slice_file_path)
        print("Details:", e)
        sys.exit(1)

    return slice_ast


def parse_patterns_file(patterns_file_path):
    # Check if the file exists
    if not os.path.exists(patterns_file_path):
        print("Error: File Not Found:", patterns_file_path)
        sys.exit(1)

    if DEBUG:
        debug_print("[DEBUG] Reading patterns file: {}".format(patterns_file_path))

    try:
        # Read and parse the patterns file
        with open(patterns_file_path, "r") as f:
            patterns = json.load(f)

        if DEBUG:
            debug_print("[DEBUG] Patterns file loaded successfully ({} patterns)".format(len(patterns)))
            for i, p in enumerate(patterns):
                debug_print("[DEBUG]   Pattern {}: {}".format(i+1, p.get('vulnerability')))
    except json.JSONDecodeError as e:
        print("Error: Invalid JSON in Patterns File:", patterns_file_path)
        print("Details:", e)
        sys.exit(1)

    return patterns


def analyze_slice_with_patterns(slice_ast, patterns):
    if DEBUG:
        debug_print("[DEBUG] Initializing vulnerability finder...")

    # Initialize the vulnerability finder with the given patterns
    analyser = VulnerabilityFinder(patterns)

    if DEBUG:
        debug_print("[DEBUG] Visiting AST to find vulnerabilities...")

    # Visit the AST of the slice to find vulnerabilities
    analyser.visit(slice_ast)

    if DEBUG:
        debug_print("[DEBUG] AST visit complete")
        debug_print("[DEBUG] Final tainted variables: {}".format(list(analyser.tainted_vars.keys())))

    # Sort vulnerabilities to ensure deterministic output grouped by vulnerability type
    def sort_key(vuln):
        v_id = vuln['vulnerability']
        # Split by last underscore to separate name and count
        if '_' in v_id:
            name, num = v_id.rsplit('_', 1)
            if num.isdigit():
                # Primary key: Index in family order
                if name in analyser.vuln_family_order:
                    family_index = analyser.vuln_family_order.index(name)
                else:
                    family_index = float('inf') # Should not happen
                
                return (family_index, int(num))
        return (float('inf'), 0)

    analyser.vulnerabilities.sort(key=sort_key)

    # Return the found vulnerabilities
    return analyser.vulnerabilities


def output_analysis_results(results, slice_file_path):
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Build output file path
    output_file_path = os.path.join(
        OUTPUT_DIR,
        os.path.splitext(os.path.basename(slice_file_path))[0] + ".output.json"
    )

    if DEBUG:
        debug_print("[DEBUG] Writing results to: {}".format(output_file_path))

    # Write results to output file
    with open(output_file_path, "w") as f:
        json.dump(results, f, indent=4)

    if DEBUG:
        debug_print("[DEBUG] Results written successfully")


def main():
    global DEBUG_FILE

    if len(sys.argv) != 3:
        print("Error: Incorrect Number of Arguments\nUsage: python ./py_analyser.py foo/slice_1.py bar/my_patterns.json")
        sys.exit(1)

    slice_file_path = sys.argv[1]
    patterns_file_path = sys.argv[2]

    # Open debug file if DEBUG is enabled
    if DEBUG:
        os.makedirs(DEBUG_DIR, exist_ok=True)
        debug_file_path = os.path.join(
            DEBUG_DIR,
            os.path.splitext(os.path.basename(slice_file_path))[0] + ".debug.txt"
        )
        DEBUG_FILE = open(debug_file_path, "w")
        debug_print("[DEBUG] Starting analysis...")

    try:
        # Read and Parse the slice file
        slice_ast = parse_slice_file(slice_file_path)

        # Read and Parse the patterns file
        patterns = parse_patterns_file(patterns_file_path)

        # Perform analysis based on the patterns
        results = analyze_slice_with_patterns(slice_ast, patterns)

        if DEBUG:
            debug_print("[DEBUG] Analysis complete. Found {} vulnerabilities".format(len(results)))

        # Output the results of the analysis
        output_analysis_results(results, slice_file_path)

        if DEBUG:
            debug_print("[DEBUG] Results written to output file")
    finally:
        # Close debug file
        if DEBUG and DEBUG_FILE:
            DEBUG_FILE.close()

if __name__ == "__main__":
    main()