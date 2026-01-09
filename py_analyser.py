# Imports
import ast
import json
import os
import sys
import copy


# Output directory
OUTPUT_DIR = "./output"

# AST visitor to find vulnerabilities
class VulnerabilityFinder(ast.NodeVisitor):
    def __init__(self, patterns):
        self.patterns = patterns
        for i, p in enumerate(self.patterns):
            p['_index'] = i

        self.tainted_vars = {}         # Tracks tainted variables
        self.assigned_vars = set()     # Tracks assigned variables
        self.vulnerabilities = []      # List of found vulnerabilities
        self.guards = []               # Stack of guard flows

        self.sources_map = {}          # Maps sources to patterns
        self.sinks_map = {}            # Maps sinks to patterns
        self.sanitizers_map = {}       # Maps sanitizers to patterns
        self.guard_sanitizers = []     # Stack of sanitizers in guards

        self.vuln_family_order = []    # Order of vulnerability families
        self.vulnerability_count = {}  # Counter for vulnerabilities

        self._build_patterns_maps()    # Build lookup maps


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
    
    # Find sanitizers present in all explicit flows of a condition
    def _get_common_sanitizers(self, flows):
        if not flows:
            return []

        # Only explicit flows affect the sanitizer set; implicit flows
        # (control-dependence baggage) must not remove sanitizers from the value.
        explicit_flows = [f for f in flows if not f.get('implicit', False)]
        
        # Prefer explicit flows; if none exist, fall back to all flows.
        target_flows = explicit_flows if explicit_flows else flows
        
        # Helper to convert sanitizer list [name, line] to tuple (name, line)
        def to_tuple(s): return tuple(s)
        
        # Start with sanitizers from the first flow
        common_set = set(to_tuple(s) for s in target_flows[0]['sanitizers'])
        
        # Intersect with sanitizers from remaining flows
        for f in target_flows[1:]:
            current_set = set(to_tuple(s) for s in f['sanitizers'])
            common_set &= current_set
            
        # Convert back to list of lists [ [name, line], ... ]
        return sorted([list(s) for s in common_set], key=lambda x: (x[1], x[0]))


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

        elif isinstance(node, ast.Compare):
            flows.extend(self._resolve_flows(node.left))
            for comparator in node.comparators:
                flows.extend(self._resolve_flows(comparator))

        elif isinstance(node, ast.Call):
            # Get function/method name
            func_name = self._extract_call_name(node.func)
            # Resolve flows for all arguments
            current_flows = []
            for arg in node.args:
                current_flows.extend(self._resolve_flows(arg))

            # If function is a source, add new flow
            if func_name in self.sources_map:
                for pattern in self.sources_map[func_name]:
                    current_flows.append({
                        "pattern": pattern,
                        "source": [func_name, node.lineno],
                        "sanitizers": [],
                        "implicit": False
                    })

            # If method call, propagate flows from the object
            if isinstance(node.func, ast.Attribute):
                current_flows.extend(self._resolve_flows(node.func.value))
            # If function is a sanitizer, update flows accordingly
            if func_name in self.sanitizers_map:
                sanitized_flows = []
                for flow in current_flows:
                    if func_name in flow["pattern"].get("sanitizers", []):
                        # For explicit flows, avoid idempotent sanitization (stacking the same sanitizer)
                        # This prevents infinite growth in loops like a = s(a)
                        sanitizer_entry = [func_name, node.lineno]
                        if sanitizer_entry in flow["sanitizers"]:
                            sanitized_flows.append(flow)
                            continue

                        new_flow = copy.deepcopy(flow)
                        new_flow["sanitizers"].append(sanitizer_entry)
                        sanitized_flows.append(new_flow)
                    else:
                        sanitized_flows.append(flow)
                flows.extend(sanitized_flows)
            else:
                flows.extend(current_flows)

        elif isinstance(node, ast.Attribute):
            # Resolve flows for the base object
            flows.extend(self._resolve_flows(node.value))

        elif isinstance(node, ast.Subscript):
            # Resolve flows for the base and the index
            flows.extend(self._resolve_flows(node.value))
            flows.extend(self._resolve_flows(node.slice))

        return flows

    # Remove duplicate flows by unique signature
    def _deduplicate_flows(self, flows):
        unique = []
        seen = set()
        for f in flows:
            # Build a signature for each flow (pattern, source, sanitizers, implicit)
            sanitizers_sig = tuple(tuple(s) for s in f['sanitizers'])
            sig = (f['pattern']['_index'], tuple(f['source']), sanitizers_sig, f['implicit'])
            # Only add flows that haven't been seen yet
            if sig not in seen:
                seen.add(sig)
                unique.append(f)
        # Return list of unique flows
        return unique


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

        # Collect active sanitizers from all guard levels
        active_sanitizers = []
        for s_list in self.guard_sanitizers:
            active_sanitizers.extend(s_list)

        new_flows = list(flows)
        for g_flow in guard_flows:
            # Mark guard flows as implicit
            implicit_flow = copy.deepcopy(g_flow)
            implicit_flow['implicit'] = True
            new_flows.append(implicit_flow)
            
            # Add enriched implicit flow representing combined guard paths
            # (e.g., loop guard + nested if guard)
            enriched_implicit = copy.deepcopy(g_flow)
            enriched_implicit['implicit'] = True
            
            # Apply sanitizers from surrounding guards
            current_sanitizers = set(tuple(s) for s in enriched_implicit['sanitizers'])
            for sanitizer in active_sanitizers:
                s_tuple = tuple(sanitizer)
                if s_tuple not in current_sanitizers:
                    enriched_implicit['sanitizers'].append(sanitizer)
                    current_sanitizers.add(s_tuple)
            
            # Always add; _deduplicate_flows will remove duplicates if raw == enriched
            new_flows.append(enriched_implicit)
            
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
                    if isinstance(target, ast.Attribute):
                        # Check if attribute is a sink
                        attr_name = target.attr
                        self._check_sinks(attr_name, node.lineno, assigned_flows)
                    self._check_sinks(root_name, node.lineno, self.tainted_vars[root_name])
        for target in node.targets:
            # Visit subscript indices
            if isinstance(target, ast.Subscript):
                self.visit(target.slice)


    # Handle function/method calls
    def visit_Call(self, node):
        func_name = self._extract_call_name(node.func)

        # Visit all children nodes
        self.generic_visit(node)
        
        # If function is a sink, check arguments
        if func_name and func_name in self.sinks_map:
            arg_flows = []
            for arg in node.args:
                arg_flows.extend(self._resolve_flows(arg))
            self._check_sinks(func_name, node.lineno, arg_flows)


    # Handle if statements and merge taint states
    def visit_If(self, node):
        # If the condition is tainted, all flows inside become implicit
        cond_flows = self._resolve_flows(node.test)
        self.guards.append(cond_flows)

        common_sanitizers = self._get_common_sanitizers(cond_flows)
        self.guard_sanitizers.append(common_sanitizers)

        # Save current state before entering branches
        assigned_before = self.assigned_vars.copy()
        tainted_before = copy.deepcopy(self.tainted_vars)
        
        # Visit the if branch
        for child in node.body:
            self.visit(child)
        assigned_after_if = self.assigned_vars.copy()
        tainted_after_if = copy.deepcopy(self.tainted_vars)
        
        # Reset to before state and visit else branch (if exists)
        self.assigned_vars = assigned_before.copy()
        self.tainted_vars = copy.deepcopy(tainted_before)
        
        if node.orelse:
            for child in node.orelse:
                self.visit(child)
            assigned_after_else = self.assigned_vars.copy()
            tainted_after_else = copy.deepcopy(self.tainted_vars)
            
            # After if-else, merge the states:
            # Only variables assigned in BOTH branches are definitely assigned
            self.assigned_vars = assigned_after_if & assigned_after_else
            
            # Merge tainted_vars: collect flows from both branches
            all_vars = set(tainted_after_if.keys()) | set(tainted_after_else.keys())
            merged_tainted = {}
            for var in all_vars:
                flows_if = tainted_after_if.get(var, [])
                flows_else = tainted_after_else.get(var, [])
                merged_tainted[var] = self._deduplicate_flows(flows_if + flows_else)
            self.tainted_vars = merged_tainted
        else:
            # If there's no else, we can't assume variables are assigned
            # (because the if might not execute)
            self.assigned_vars = assigned_before
            
            # For tainted_vars, we need to keep flows from before AND after the if
            all_vars = set(tainted_before.keys()) | set(tainted_after_if.keys())
            merged_tainted = {}
            for var in all_vars:
                flows_before = tainted_before.get(var, [])
                flows_after = tainted_after_if.get(var, [])
                merged_tainted[var] = self._deduplicate_flows(flows_before + flows_after)
            self.tainted_vars = merged_tainted
        
        self.guards.pop()
        self.guard_sanitizers.pop()


    # Handle while loops with fixed-point iteration
    def visit_While(self, node):
        # A loop might run 0 times (keeping Pre-Loop state) or N times.
        # We must maintain the union of Pre-Loop state and the state resulting from iterations.
        
        pre_loop_vars = copy.deepcopy(self.tainted_vars)
        current_vars = copy.deepcopy(self.tainted_vars)

        # Run up to 10 iterations to reach a fixed point
        for _ in range(10):
            # Start iteration with current assumption of variables
            self.tainted_vars = copy.deepcopy(current_vars)
            
            # Treat loop condition as implicit flow
            cond_flows = self._resolve_flows(node.test)
            self.guards.append(cond_flows)
            
            # Calculate and push common sanitizers
            common_sanitizers = self._get_common_sanitizers(cond_flows)
            self.guard_sanitizers.append(common_sanitizers)

            for stmt in node.body:
                self.visit(stmt)

            self.guards.pop()
            self.guard_sanitizers.pop()

            # New_State = Pre_Loop U Body(Current_State)
            # This ensures we capture the case where loop is skipped (Pre_Loop)
            # and cases where loop runs (Body output).
            next_state = {}
            all_keys = set(pre_loop_vars.keys()) | set(self.tainted_vars.keys())
            
            for k in all_keys:
                flows_pre = pre_loop_vars.get(k, [])
                flows_body = self.tainted_vars.get(k, [])
                next_state[k] = self._deduplicate_flows(flows_pre + flows_body)
            
            # Check for convergence
            state_before_json = json.dumps(current_vars, default=str, sort_keys=True)
            state_after_json = json.dumps(next_state, default=str, sort_keys=True)
            
            current_vars = next_state
            if state_before_json == state_after_json:
                break
        
        self.tainted_vars = current_vars
    

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
    # Check if the file exists
    if not os.path.exists(path):
        print("Error: File Not Found:", path)
        sys.exit(1)
    
    try:
        # Read and parse the slice file
        with open(path, "r") as f:
            slice_code = f.read()
        slice_ast = ast.parse(slice_code)
    except SyntaxError as e:
        print("Error: Syntax Error in Slice File:", path)
        print("Details:", e)
        sys.exit(1)

    return slice_ast


# Parse the patterns JSON file
def parse_patterns_file(path):
    # Check if the file exists
    if not os.path.exists(path):
        print("Error: File Not Found:", path)
        sys.exit(1)
    
    try:
        # Read and parse the patterns file
        with open(path, "r") as f:
            patterns = json.load(f)
    except json.JSONDecodeError as e:
        print("Error: Invalid JSON in Patterns File:", path)
        print("Details:", e)
        sys.exit(1)

    return patterns


# Analyze the slice AST with given patterns
def analyze_slice_with_patterns(slice_ast, patterns):
    # Initialize the vulnerability finder with the given patterns
    analyser = VulnerabilityFinder(patterns)

    # Visit the AST of the slice to find vulnerabilities
    analyser.visit(slice_ast)

    # Return the found vulnerabilities sorted
    return analyser.get_sorted_results()


# Write results to output file
def output_results(results, path):
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Build output file path
    out_path = os.path.join(
        OUTPUT_DIR,
        os.path.splitext(os.path.basename(path))[0] + ".output.json"
    )

    # Write results to output file
    with open(out_path, "w") as f:
        json.dump(results, f, indent=4)


# Main entry point
def main():
    if len(sys.argv) != 3:
        print("Error: Incorrect Number of Arguments\nUsage: python ./py_analyser.py foo/slice_1.py bar/my_patterns.json")
        sys.exit(1)

    slice_path, patterns_path = sys.argv[1], sys.argv[2]

    try:
        # Read and Parse the slice file
        slice_ast = parse_slice_file(slice_path)

        # Read and Parse the patterns file
        patterns = parse_patterns_file(patterns_path)

        # Perform analysis based on the patterns
        results = analyze_slice_with_patterns(slice_ast, patterns)

        # Output the results of the analysis
        output_results(results, slice_path)
    except Exception as e:
        # Print error if any
        print(f"Error: {e}")


# Run main if executed as script
if __name__ == "__main__":
    main()