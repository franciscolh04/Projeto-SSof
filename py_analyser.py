import ast
import json
import os
import sys

OUTPUT_DIR = "./output"

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

    def _build_patterns_maps(self):
        for pattern in self.patterns:
            # Build sources map
            for source_name in pattern.get("sources", []):
                if source_name not in self.sources_map:
                    self.sources_map[source_name] = []
                self.sources_map[source_name].append(pattern)

            # Build sanitizers map
            for sanitizer_name in pattern.get("sanitizers", []):
                if sanitizer_name not in self.sanitizers_map:
                    self.sanitizers_map[sanitizer_name] = []
                self.sanitizers_map[sanitizer_name].append(pattern)

            # Build sinks map
            for sink_name in pattern.get("sinks", []):
                if sink_name not in self.sinks_map:
                    self.sinks_map[sink_name] = []
                self.sinks_map[sink_name].append(pattern)

    def _extract_node_name(self, node):
        if isinstance(node, ast.Name): # Variable or function name
            return node.id
        elif isinstance(node, ast.Call): # Function call
            return self._extract_node_name(node.func)
        elif isinstance(node, ast.Attribute): # Attribute access
            value_name = self._extract_node_name(node.value)
            if value_name:
                return f"{value_name}.{node.attr}"
        elif isinstance(node, ast.Subscript): # Subscript access
            return self._extract_node_name(node.value)
        return None
    
    def _sort_flows(self, flows):
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
            
            return (history_index, json_index)
        
        return sorted(flows, key=sort_key)
    
    def _get_flows_from_node(self, node):
        flows = []
        
        if isinstance(node, ast.Name):
            var_name = node.id
            
            # If the variable is tainted, copy all its flows
            if var_name in self.tainted_vars:
                for flow in self.tainted_vars[var_name]:
                    flows.append(flow.copy())

            # Check if the variable is a Source itself
            if var_name in self.sources_map:
                for pattern in self.sources_map[var_name]:
                    flows.append({
                        "pattern": pattern,
                        "source": [var_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    })

            # Check if it is a Non-Instantiated Variable (Implicit Source)
            if var_name not in self.assigned_vars and var_name not in self.sources_map:
                # Add as source for all patterns
                for pattern in self.patterns:
                    flows.append({
                        "pattern": pattern,
                        "source": [var_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    })

        elif isinstance(node, ast.BinOp):
            flows.extend(self._get_flows_from_node(node.left))
            flows.extend(self._get_flows_from_node(node.right))

        elif isinstance(node, ast.UnaryOp):
            flows.extend(self._get_flows_from_node(node.operand))

        elif isinstance(node, ast.Call):
            for arg in node.args:
                flows.extend(self._get_flows_from_node(arg))

        elif isinstance(node, ast.Attribute):
            flows.extend(self._get_flows_from_node(node.value)) 

        elif isinstance(node, ast.Subscript):
            flows.extend(self._get_flows_from_node(node.value))

        return flows
    
    def _report_vulnerability(self, sink_name, sink_lineno, flow):
        pattern = flow['pattern']

        # Keep track of vulnerability family order
        vuln_name_base = pattern['vulnerability']
        if vuln_name_base not in self.vuln_family_order:
            self.vuln_family_order.append(vuln_name_base)

        source_id = flow['source']
        
        # Check if this vulnerability has already been reported
        for vuln in self.vulnerabilities:
            if (vuln['vulnerability'].startswith(vuln_name_base) and 
                vuln['source'] == source_id and 
                vuln['sink'] == [sink_name, sink_lineno]):
                
                # Add new flow if it's not already present
                new_flow_entry = [
                    "implicit" if flow['implicit'] else "explicit",
                    flow['sanitizers']
                ]
                if new_flow_entry not in vuln['flows']:
                    vuln['flows'].append(new_flow_entry)
                return

        # If not found, create a new entry
        if vuln_name_base not in self.vulnerability_count:
            self.vulnerability_count[vuln_name_base] = 0
        self.vulnerability_count[vuln_name_base] += 1
        
        # Create new vulnerability report entry and add to the list
        vulnerability_report = {
            "vulnerability": f"{vuln_name_base}_{self.vulnerability_count[vuln_name_base]}",
            "source": flow['source'],
            "sink": [sink_name, sink_lineno],
            "flows": [
                [
                    "implicit" if flow['implicit'] else "explicit",
                    flow['sanitizers']
                ]
            ]
        }
        self.vulnerabilities.append(vulnerability_report)
    
    def visit_Assign(self, node):
        # Visit the value to catch any nested assignments
        self.generic_visit(node)

        # Get Target and Value Names
        if not isinstance(node.targets[0], ast.Name):
            return
        target_name = node.targets[0].id
        value_name = self._extract_node_name(node.value)

        # Mark the variable as assigned to avoid implicit source detection
        self.assigned_vars.add(target_name)

        # Initialize collected flows for this assignment
        collected_flows = []

        incoming_flows = self._get_flows_from_node(node.value)

        # If the value is a sanitizer
        if value_name in self.sanitizers_map:
            for flow in incoming_flows:
                # If the sanitizer is part of the pattern, add it to the flow
                if value_name in flow["pattern"].get("sanitizers", []):
                    flow["sanitizers"] = flow["sanitizers"] + [[value_name, node.lineno]]
                collected_flows.append(flow)
        else:
            # If not a sanitizer, propagate the flows as they are
            collected_flows.extend(incoming_flows)

        # If the value assigned is from a source
        if value_name in self.sources_map:
             for pattern in self.sources_map[value_name]:
                collected_flows.append({
                    "pattern": pattern,
                    "source": [value_name, node.lineno],
                    "sanitizers": [],
                    "implicit": False
                })

        # Assign the collected flows to the target variable
        if collected_flows:
            self.tainted_vars[target_name] = collected_flows

            # If the target variable is a sink
            if target_name in self.sinks_map:

                sorted_flows = self._sort_flows(collected_flows)
                for flow in sorted_flows:
                    # Check each flow for matching patterns
                    if target_name in flow['pattern'].get('sinks', []):
                        self._report_vulnerability(target_name, node.lineno, flow)

        # If no tainted flows, remove the variable from tainted vars
        elif target_name in self.tainted_vars:
            del self.tainted_vars[target_name]


    def visit_Call(self, node):
        # Visit the call arguments to catch any nested calls
        self.generic_visit(node)

        # Get the function name being called
        func_name = self._extract_node_name(node.func)

        # Check if the function called is a sink
        if func_name in self.sinks_map:
            all_flows = []

            # Collect flows from all arguments
            for arg in node.args:
                all_flows.extend(self._get_flows_from_node(arg))
 
            if not all_flows:
                return

            # Check each flow for matching patterns
            sorted_flows = self._sort_flows(all_flows)
            for flow in sorted_flows:
                pattern = flow["pattern"]
                if func_name in pattern.get("sinks", []):
                    self._report_vulnerability(func_name, node.lineno, flow)
    
    def visit_Expr(self, node):
        # Visit expressions to catch any nested calls or assignments
        self.generic_visit(node)

def parse_slice_file(slice_file_path):
    # Check if the file exists
    if not os.path.exists(slice_file_path):
        print("Error: File Not Found:", slice_file_path)
        sys.exit(1)
    
    try:
        # Read and parse the slice file
        with open(slice_file_path, "r") as f:
            slice_code = f.read()
        slice_ast = ast.parse(slice_code)
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
    
    try:
        # Read and parse the patterns file
        with open(patterns_file_path, "r") as f:
            patterns = json.load(f)
    except json.JSONDecodeError as e:
        print("Error: Invalid JSON in Patterns File:", patterns_file_path)
        print("Details:", e)
        sys.exit(1)

    return patterns


def analyze_slice_with_patterns(slice_ast, patterns):
    # Initialize the vulnerability finder with the given patterns
    analyser = VulnerabilityFinder(patterns)

    # Visit the AST of the slice to find vulnerabilities
    analyser.visit(slice_ast)

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

    # Write results to output file
    with open(output_file_path, "w") as f:
        json.dump(results, f, indent=4)


def main():
    if len(sys.argv) != 3:
        print("Error: Incorrect Number of Arguments\nUsage: python ./py_analyser.py foo/slice_1.py bar/my_patterns.json")
        sys.exit(1)
    
    slice_file_path = sys.argv[1]
    patterns_file_path = sys.argv[2]

    # Read and Parse the slice file
    slice_ast = parse_slice_file(slice_file_path)

    # Read and Parse the patterns file
    patterns = parse_patterns_file(patterns_file_path)

    # Perform analysis based on the patterns
    results = analyze_slice_with_patterns(slice_ast, patterns)

    # Output the results of the analysis
    output_analysis_results(results, slice_file_path)

if __name__ == "__main__":
    main()