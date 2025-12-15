import ast
import json
import os
import sys

OUTPUT_DIR = "./output"

class VulnerabilityFinder(ast.NodeVisitor):
    def __init__(self, patterns):
        self.patterns = patterns
        self.tainted_vars = {}
        self.vulnerabilities = []

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
    
    def _get_tainted_vars_from_node(self, node):
        if isinstance(node, ast.Name):
            return [node.id] if node.id in self.tainted_vars else []
        elif isinstance(node, ast.BinOp):
            left_vars = self._get_tainted_vars_from_node(node.left)
            right_vars = self._get_tainted_vars_from_node(node.right)
            return left_vars + right_vars
        elif isinstance(node, ast.UnaryOp):
            return self._get_tainted_vars_from_node(node.operand)
        elif isinstance(node, ast.Call):
            tainted_vars = []
            for arg in node.args:
                tainted_vars.extend(self._get_tainted_vars_from_node(arg))
            return tainted_vars
        elif isinstance(node, ast.Attribute):
            return self._get_tainted_vars_from_node(node.value)
        elif isinstance(node, ast.Subscript):
            return self._get_tainted_vars_from_node(node.value)
        return []
    
    def visit_Assign(self, node):
        # Visit the value to catch any nested assignments
        self.generic_visit(node)

        # Get Target and Value Names
        if not isinstance(node.targets[0], ast.Name):
            return
        target_name = node.targets[0].id
        value_name = self._extract_node_name(node.value)

        # Initialize collected flows for this assignment
        collected_flows = []

        # Check for tainted variables in the expression
        tainted_in_expr = self._get_tainted_vars_from_node(node.value)

        if tainted_in_expr:
            # If the value is a sanitizer
            if value_name in self.sanitizers_map:
                for arg_name in tainted_in_expr:
                    source_flows = self.tainted_vars.get(arg_name, [])
                    for flow in source_flows:
                        new_flow = flow.copy()
                        # If the sanitizer is part of the pattern, add it to the flow
                        if value_name in new_flow["pattern"].get("sanitizers", []):
                            new_flow["sanitizers"] = flow["sanitizers"] + [[value_name, node.lineno]]
                        collected_flows.append(new_flow)
            # If the value is not a sanitizer, propagate taintedness
            else:
                for var_name in tainted_in_expr:
                    # Copy all flows from tainted variables
                    for flow in self.tainted_vars.get(var_name, []):
                        collected_flows.append(flow.copy())

        # Check if the value assigned is from a source
        if value_name in self.sources_map:
            # Create new taint flows for each pattern associated with the source
            for pattern in self.sources_map[value_name]:
                collected_flows.append(
                    {
                        "pattern": pattern,
                        "source": [value_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    }
                )

        # Assign the collected flows to the target variable
        if collected_flows:
            self.tainted_vars[target_name] = collected_flows

            # If the target variable is a sink, check for vulnerabilities
            if target_name in self.sinks_map:
                # Check each flow for matching patterns
                for flow in collected_flows:
                    pattern = flow['pattern']

                    if target_name in pattern.get('sinks', []):
                        vulnerability = pattern['vulnerability']

                        # Count occurrences of the vulnerability to append a unique suffix
                        if vulnerability not in self.vulnerability_count:
                            self.vulnerability_count[vulnerability] = 0
                        self.vulnerability_count[vulnerability] += 1

                        # Prepare the vulnerability report
                        vulnerability_report = {
                            "vulnerability": f"{vulnerability}_{self.vulnerability_count[vulnerability]}",
                            "source": flow['source'],
                            "sink": [target_name, node.lineno],
                            "flows": [
                                [
                                    "implicit" if flow['implicit'] else "explicit",
                                    flow['sanitizers']
                                ]
                            ]
                        }

                        # Avoid duplicate reports
                        if vulnerability_report not in self.vulnerabilities:
                            self.vulnerabilities.append(vulnerability_report)

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
            tainted_args = []
            # Get tainted arguments passed to the sink
            for arg in node.args:
                tainted_args.extend(self._get_tainted_vars_from_node(arg))

            # If no tainted arguments, return
            if not tainted_args:
                return

            # For each tainted argument, check for vulnerabilities
            for arg_name in tainted_args:
                flows = self.tainted_vars.get(arg_name, [])

                # Check each flow for matching patterns
                for flow in flows:
                    pattern = flow["pattern"]

                    # If the sink matches the pattern, report vulnerability
                    if func_name in pattern.get("sinks", []):
                        vulnerability = pattern['vulnerability']

                        # Count occurrences of the vulnerability to append a unique suffix
                        if vulnerability not in self.vulnerability_count:
                            self.vulnerability_count[vulnerability] = 0
                        self.vulnerability_count[vulnerability] += 1

                        # Prepare the vulnerability report
                        vulnerability_report = {
                            "vulnerability": f"{vulnerability}_{self.vulnerability_count[vulnerability]}",
                            "source": flow["source"],
                            "sink": [func_name, node.lineno],
                            "flows": [
                                [
                                    "implicit" if flow["implicit"] else "explicit",
                                    flow["sanitizers"]
                                ]
                            ]
                        }

                        # Avoid duplicate reports
                        if vulnerability_report not in self.vulnerabilities:
                            self.vulnerabilities.append(vulnerability_report)
    
    def visit_Expr(self, node):
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