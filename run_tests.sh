#!/bin/bash


# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'


# Paths to main files and directories
ANALYSER="./py_analyser.py"
OUTPUT_DIR="./output"
SLICES_DIR="./slices"


# Test counters
PASSED=0
FAILED=0
TOTAL=0


# Print test suite header
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}      STARTING PY_ANALYSER TESTS     ${NC}"
echo -e "${BLUE}========================================${NC}"


# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"


# Compare two JSON files after recursively sorting them
compare_json() {
    python3 -c "
import sys, json
def sort_json(obj):
    if isinstance(obj, dict):
        return {k: sort_json(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list):
        try:
            return sorted((sort_json(x) for x in obj), key=lambda x: json.dumps(x, sort_keys=True))
        except Exception:
            return obj
    else:
        return obj
try:
    with open('$1') as f1, open('$2') as f2:
        j1 = sort_json(json.load(f1))
        j2 = sort_json(json.load(f2))
        print(j1 == j2)
except Exception as e:
    print('False')
"
}


# Iterate over all Python slice files and run tests
while read slice_file; do
    # Skip empty lines
    if [ -z "$slice_file" ]; then continue; fi

    TOTAL=$((TOTAL+1))

    # Build file names for each test case
    base_name=$(basename "$slice_file" .py)
    dir_name=$(dirname "$slice_file")

    patterns_file="${dir_name}/${base_name}.patterns.json"
    expected_output_file="${dir_name}/${base_name}.output.json"
    generated_output_file="${OUTPUT_DIR}/${base_name}.output.json"

    # Skip test if required files are missing
    if [ ! -f "$patterns_file" ] || [ ! -f "$expected_output_file" ]; then
        echo -e "${YELLOW}[SKIP]${NC} Missing files for: $base_name"
        TOTAL=$((TOTAL-1))
        continue
    fi

    # Run the analyser script
    python3 "$ANALYSER" "$slice_file" "$patterns_file" > /dev/null 2>&1
    exit_code=$?

    # Check for execution errors
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}[FAIL]${NC} Execution error in slice: $base_name (Code: $exit_code)"
        FAILED=$((FAILED+1))
        continue
    fi

    # Compare generated and expected outputs
    result=$(compare_json "$expected_output_file" "$generated_output_file")

    # Print test result
    if [ "$result" == "True" ]; then
        echo -e "${GREEN}[PASS]${NC} $base_name"
        PASSED=$((PASSED+1))
    else
        echo -e "${RED}[FAIL]${NC} $base_name"
        echo -e "       Expected: $expected_output_file"
        echo -e "       Got:      $generated_output_file"
        FAILED=$((FAILED+1))
    fi

done < <(find "$SLICES_DIR" -type f -name "*.py" | sort)


# Print summary of test results
echo -e "${BLUE}========================================${NC}"
echo -e "Test Summary:"
echo -e "Total:  $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}Failed: 0${NC}"
    exit 0
fi