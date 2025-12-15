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

        # Check if the value assigned is from a source
        if value_name in self.sources_map:
            new_flows = []
            # Create new taint flows for each pattern associated with the source
            for pattern in self.sources_map[value_name]:
                new_flows.append(
                    {
                        "pattern": pattern,
                        "source": [value_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    }
                )
            # Assign the new flows to the target variable
            self.tainted_vars[target_name] = new_flows
            return
        # Check if the value assigned is from a sanitizer
        elif value_name in self.sanitizers_map:
            # Get tainted args from the sanitizer call
            tainted_args = self._get_tainted_vars_from_node(node.value)

            if tainted_args:
                final_flows = []
                # Copy flows from all tainted args and add sanitizer info
                for arg_name in tainted_args:
                    source_flows = self.tainted_vars.get(arg_name, [])

                    for flow in source_flows:
                        new_flow = flow.copy()

                        current_pattern = new_flow["pattern"]
                        if value_name in current_pattern.get("sanitizers", []):
                            new_flow["sanitizers"] = flow["sanitizers"] + [[value_name, node.lineno]]
                        
                        final_flows.append(new_flow)

                # Assign the combined flows to the target variable
                if final_flows:
                    self.tainted_vars[target_name] = final_flows
                    return
        # Check if the value assigned is from a tainted variable
        else:
            # Get tainted variables in the expression
            tainted_in_expr = self._get_tainted_vars_from_node(node.value)

            if tainted_in_expr:
                final_flows = []
                # Copy flows from all tainted variables in the expression
                for var_name in tainted_in_expr:
                    flows_to_copy = [f.copy() for f in self.tainted_vars.get(var_name, [])]
                    final_flows.extend(flows_to_copy)

                # Assign the combined flows to the target variable
                self.tainted_vars[target_name] = final_flows

            # If no tainted variables, remove target from tainted vars
            elif target_name in self.tainted_vars:
                del self.tainted_vars[target_name]


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
        json.dump(results, f, indent=2)


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