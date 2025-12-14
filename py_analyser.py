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