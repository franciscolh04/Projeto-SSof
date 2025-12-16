#!/bin/bash

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
ANALYSER="./py_analyser.py"
OUTPUT_DIR="./output"
SLICES_DIR="./slices"

# Counters
PASSED=0
FAILED=0
TOTAL=0

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}      STARTING PY_ANALYSER TESTS     ${NC}"
echo -e "${BLUE}========================================${NC}"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Python function for robust JSON comparison
compare_json() {
    python3 -c "
import sys, json
try:
    with open('$1') as f1, open('$2') as f2:
        j1 = json.load(f1)
        j2 = json.load(f2)
        # Compara as estruturas de dados Python diretamente
        # Nota: json.load() carrega arrays (listas) e objetos (dicionários)
        # A comparação de listas aqui respeita a ordem, tal como pretendido.
        print(j1 == j2)
except Exception as e:
    # Se falhar a ler ou parsear, consideramos falha na comparação
    print('False')
"
}

# We use Process Substitution to avoid the subshell and keep variables
while read slice_file; do
    
    # If the line is empty (end of find), continue
    if [ -z "$slice_file" ]; then continue; fi

    TOTAL=$((TOTAL+1))
    
    # Build associated file names
    base_name=$(basename "$slice_file" .py)
    dir_name=$(dirname "$slice_file")
    
    patterns_file="${dir_name}/${base_name}.patterns.json"
    expected_output_file="${dir_name}/${base_name}.output.json"
    generated_output_file="${OUTPUT_DIR}/${base_name}.output.json"

    # Check if necessary files exist
    if [ ! -f "$patterns_file" ] || [ ! -f "$expected_output_file" ]; then
        echo -e "${YELLOW}[SKIP]${NC} Missing files for: $base_name"
        TOTAL=$((TOTAL-1)) # Do not count as test if files are missing
        continue
    fi

    # Run the Analyser
    python3 "$ANALYSER" "$slice_file" "$patterns_file" > /dev/null 2>&1
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}[FAIL]${NC} Execution error in slice: $base_name (Code: $exit_code)"
        FAILED=$((FAILED+1))
        continue
    fi

    # Compare the generated result with the expected one
    result=$(compare_json "$expected_output_file" "$generated_output_file")

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