
# Imports
import ast
import json
import os
import sys
import copy


# Output directory and debug flag
OUTPUT_DIR = "./output"
DEBUG = False


# AST visitor to find vulnerabilities
class VulnerabilityFinder(ast.NodeVisitor):
    def __init__(self, patterns):
        self.patterns = patterns
        for i, p in enumerate(self.patterns):
            p['_index'] = i

        self.tainted_vars = {}  # Tracks tainted variables
        self.assigned_vars = set()  # Tracks assigned variables
        self.vulnerabilities = []  # List of found vulnerabilities
        self.guards = []  # Stack of guard flows

        self.sources_map = {}  # Maps sources to patterns
        self.sinks_map = {}  # Maps sinks to patterns
        self.sanitizers_map = {}  # Maps sanitizers to patterns

        self.vuln_family_order = []  # Order of vulnerability families
        self.vulnerability_count = {}  # Counter for vulnerabilities

        self._build_patterns_maps()  # Build lookup maps


    # Build lookup maps for sources, sinks, and sanitizers
    def _build_patterns_maps(self):
        for pattern in self.patterns:
            # Map each source to its pattern
            for source in pattern.get("sources", []):
                self.sources_map.setdefault(source, []).append(pattern)
            # Map each sanitizer to its pattern
            for sanitizer in pattern.get("sanitizers", []):
                self.sanitizers_map.setdefault(sanitizer, []).append(pattern)
            # Map each sink to its pattern
            for sink in pattern.get("sinks", []):
                self.sinks_map.setdefault(sink, []).append(pattern)


    # Get the root variable name from an AST node
    def _get_root_name(self, node):
        # Return the root variable name for assignments and accesses
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_root_name(node.value)
        elif isinstance(node, ast.Subscript):
            return self._get_root_name(node.value)
        return None


    # Extract function or method name from a call node
    def _extract_call_name(self, node):
        # Extracts the function or method name from a call node
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None


    # Recursively resolve data flows for a node
    def _resolve_flows(self, node):
        flows = []

        if isinstance(node, ast.Name):
            # Check if variable is already tainted
            var_name = node.id
            if var_name in self.tainted_vars:
                flows.extend([copy.deepcopy(f) for f in self.tainted_vars[var_name]])
            # Check if variable is an explicit source
            if var_name in self.sources_map:
                for pattern in self.sources_map[var_name]:
                    flows.append({
                        "pattern": pattern,
                        "source": [var_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    })
            # If variable is not assigned, treat as generic source
            if var_name not in self.assigned_vars:
                for pattern in self.patterns:
                    flows.append({
                        "pattern": pattern,
                        "source": [var_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    })

        elif isinstance(node, ast.BinOp):
            # Resolve flows for both sides of the binary operation
            flows.extend(self._resolve_flows(node.left))
            flows.extend(self._resolve_flows(node.right))

        elif isinstance(node, ast.Call):
            # Get function/method name
            func_name = self._extract_call_name(node.func)
            # Resolve flows for all arguments
            arg_flows = []
            for arg in node.args:
                arg_flows.extend(self._resolve_flows(arg))
            # If method call, propagate flows from the object
            if isinstance(node.func, ast.Attribute):
                arg_flows.extend(self._resolve_flows(node.func.value))
            # If function is a source, add new flow
            if func_name in self.sources_map:
                for pattern in self.sources_map[func_name]:
                    flows.append({
                        "pattern": pattern,
                        "source": [func_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    })
            # If function is a sanitizer, update flows accordingly
            if func_name in self.sanitizers_map:
                sanitized_flows = []
                for flow in arg_flows:
                    if func_name in flow["pattern"].get("sanitizers", []):
                        new_flow = copy.deepcopy(flow)
                        new_flow["sanitizers"].append([func_name, node.lineno])
                        sanitized_flows.append(new_flow)
                    else:
                        sanitized_flows.append(flow)
                flows.extend(sanitized_flows)
            else:
                flows.extend(arg_flows)

        elif isinstance(node, ast.Attribute):
            # Resolve flows for the base object
            flows.extend(self._resolve_flows(node.value))

        elif isinstance(node, ast.Subscript):
            # Resolve flows for the base and the index
            flows.extend(self._resolve_flows(node.value))
            flows.extend(self._resolve_flows(node.slice))

        return flows


    # Add implicit context from guards to flows
    def _apply_implicit_context(self, flows):
        # If there are no guards, return flows as is
        if not self.guards:
            return flows
        guard_flows = []
        for g_list in self.guards:
            guard_flows.extend(g_list)
        # If no guard flows, return flows as is
        if not guard_flows:
            return flows
        new_flows = list(flows)
        for g_flow in guard_flows:
            # Mark guard flows as implicit
            implicit_flow = copy.deepcopy(g_flow)
            implicit_flow['implicit'] = True
            new_flows.append(implicit_flow)
        return new_flows


    # Check if a node is a sink and report vulnerabilities
    def _check_sinks(self, node_name, lineno, flows):
        # If node is not a sink, do nothing
        if node_name not in self.sinks_map:
            return
        final_flows = self._apply_implicit_context(flows)
        unique_flows = self._sort_flows(final_flows)
        for flow in unique_flows:
            pattern = flow['pattern']
            # Only report if node is a sink for this pattern
            if node_name in pattern.get('sinks', []):
                if flow['implicit'] and pattern.get('implicit') == 'no':
                    continue
                self._report_vulnerability(node_name, lineno, flow)


    # Remove duplicate flows and sort them
    def _sort_flows(self, flows):
        unique = []
        seen = set()
        for f in flows:
            # Create a unique signature for each flow
            sanitizers_sig = tuple(tuple(s) for s in f['sanitizers'])
            sig = (f['pattern']['_index'], tuple(f['source']), sanitizers_sig, f['implicit'])
            if sig not in seen:
                seen.add(sig)
                unique.append(f)
        def sort_key(f):
            # Sort by family order and pattern index
            vuln_name = f['pattern']['vulnerability']
            if vuln_name in self.vuln_family_order:
                h_idx = self.vuln_family_order.index(vuln_name)
            else:
                h_idx = 9999
            return (h_idx, f['pattern']['_index'])
        return sorted(unique, key=sort_key)


    # Add a new vulnerability finding or update an existing one
    def _report_vulnerability(self, sink_name, lineno, flow):
        pattern = flow['pattern']
        vuln_name_base = pattern['vulnerability']
        # Track the order of vulnerability families
        if vuln_name_base not in self.vuln_family_order:
            self.vuln_family_order.append(vuln_name_base)
        source_data = flow['source']
        flow_data = [
            "implicit" if flow['implicit'] else "explicit",
            flow['sanitizers']
        ]
        # Check if this vulnerability already exists
        for v in self.vulnerabilities:
            if (v['vulnerability'].rsplit('_', 1)[0] == vuln_name_base and
                v['source'] == source_data and
                v['sink'] == [sink_name, lineno]):
                if flow_data not in v['flows']:
                    v['flows'].append(flow_data)
                return
        # If new, increment count and add to list
        if vuln_name_base not in self.vulnerability_count:
            self.vulnerability_count[vuln_name_base] = 0
        self.vulnerability_count[vuln_name_base] += 1
        vuln_id = f"{vuln_name_base}_{self.vulnerability_count[vuln_name_base]}"
        self.vulnerabilities.append({
            "vulnerability": vuln_id,
            "source": source_data,
            "sink": [sink_name, lineno],
            "flows": [flow_data]
        })


    # Handle assignment statements
    def visit_Assign(self, node):
        # Resolve flows for right-hand side
        rhs_flows = self._resolve_flows(node.value)
        assigned_flows = self._apply_implicit_context(rhs_flows)
        # Visit right-hand side for sinks
        self.visit(node.value)
        for target in node.targets:
            # Get root variable name for each assignment target
            root_name = self._get_root_name(target)
            if root_name:
                if isinstance(target, ast.Name):
                    # Direct assignment to variable
                    self.assigned_vars.add(root_name)
                    self.tainted_vars[root_name] = copy.deepcopy(assigned_flows)
                    self._check_sinks(root_name, node.lineno, assigned_flows)
                elif isinstance(target, (ast.Attribute, ast.Subscript)):
                    # Assignment to attribute or subscript
                    if root_name not in self.tainted_vars:
                        self.tainted_vars[root_name] = []
                    self.tainted_vars[root_name].extend(copy.deepcopy(assigned_flows))
                    if isinstance(target, ast.Subscript):
                        # Add flows from index
                        index_flows = self._resolve_flows(target.slice)
                        self.tainted_vars[root_name].extend(copy.deepcopy(index_flows))
                    self._check_sinks(root_name, node.lineno, self.tainted_vars[root_name])
                    if isinstance(target, ast.Attribute):
                        # Check if attribute is a sink
                        attr_name = target.attr
                        self._check_sinks(attr_name, node.lineno, assigned_flows)
        for target in node.targets:
            # Visit subscript indices
            if isinstance(target, ast.Subscript):
                self.visit(target.slice)


    # Handle function/method calls
    def visit_Call(self, node):
        func_name = self._extract_call_name(node.func)
        # If function is a sink, check arguments
        if func_name and func_name in self.sinks_map:
            arg_flows = []
            for arg in node.args:
                arg_flows.extend(self._resolve_flows(arg))
            self._check_sinks(func_name, node.lineno, arg_flows)
        # Visit all children nodes
        self.generic_visit(node)


    # Handle if statements and merge taint states
    def visit_If(self, node):
        # Resolve flows for condition
        cond_flows = self._resolve_flows(node.test)
        self.guards.append(cond_flows)
        # Save state before if-branch
        state_before = {k: [copy.deepcopy(f) for f in v] for k, v in self.tainted_vars.items()}
        # Visit if-branch
        for stmt in node.body:
            self.visit(stmt)
        # Save state after if-branch
        state_after_if = {k: [copy.deepcopy(f) for f in v] for k, v in self.tainted_vars.items()}
        # Restore state and visit else-branch
        self.tainted_vars = {k: [copy.deepcopy(f) for f in v] for k, v in state_before.items()}
        for stmt in node.orelse:
            self.visit(stmt)
        # Save state after else-branch
        state_after_else = {k: [copy.deepcopy(f) for f in v] for k, v in self.tainted_vars.items()}
        # Merge taint states from both branches
        self.tainted_vars = self._merge_states(state_after_if, state_after_else)
        self.guards.pop()


    # Merge taint states from two branches
    def _merge_states(self, state1, state2):
        # Merge flows for all variable keys
        all_keys = set(state1.keys()) | set(state2.keys())
        merged = {}
        for k in all_keys:
            flows1 = state1.get(k, [])
            flows2 = state2.get(k, [])
            merged[k] = flows1 + flows2
        return merged


    # Handle while loops with fixed-point iteration
    def visit_While(self, node):
        # Fixed-point iteration for while loops (max 10)
        for _ in range(10):
            # Save state before loop
            state_before = json.dumps(self.tainted_vars, default=str, sort_keys=True)
            # Resolve flows for loop condition
            cond_flows = self._resolve_flows(node.test)
            self.guards.append(cond_flows)
            # Visit loop body
            for stmt in node.body:
                self.visit(stmt)
            self.guards.pop()
            # Save state after loop
            state_after = json.dumps(self.tainted_vars, default=str, sort_keys=True)
            # Stop if state converges
            if state_before == state_after:
                break
    

    # Return sorted list of vulnerabilities for output
    def get_sorted_results(self):
        def sort_key(vuln):
            vuln_id = vuln['vulnerability']
            family = vuln_id.rsplit('_', 1)[0]
            if family in self.vuln_family_order:
                family_idx = self.vuln_family_order.index(family)
            else:
                family_idx = 9999
            return (family_idx, vuln_id)
        # Return sorted vulnerabilities for output
        return sorted(self.vulnerabilities, key=sort_key)

# Parse a Python file and return its AST
def parse_slice_file(path):
    with open(path, "r") as f:
        # Parse file contents to AST
        return ast.parse(f.read())

# Parse the patterns JSON file
def parse_patterns_file(path):
    with open(path, "r") as f:
        # Load JSON patterns
        return json.load(f)

# Write results to output file
def output_results(results, path):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, os.path.splitext(os.path.basename(path))[0] + ".output.json")
    with open(out_path, "w") as f:
        # Dump results as pretty JSON
        json.dump(results, f, indent=4)


# Main entry point
def main():
    if len(sys.argv) != 3:
        return
    slice_path, patterns_path = sys.argv[1], sys.argv[2]
    try:
        # Parse input files
        slice_ast = parse_slice_file(slice_path)
        patterns = parse_patterns_file(patterns_path)
        # Run analysis
        analyser = VulnerabilityFinder(patterns)
        analyser.visit(slice_ast)
        final_results = analyser.get_sorted_results()
        # Output results
        output_results(final_results, slice_path)
    except Exception as e:
        # Print error if any
        print(f"Error: {e}")


# Run main if executed as script
if __name__ == "__main__":
    main()