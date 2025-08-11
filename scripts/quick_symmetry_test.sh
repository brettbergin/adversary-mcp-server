#!/bin/bash

# Quick Symmetry Test: Compare MCP tools with CLI results
# This test ensures MCP and CLI produce identical results for the same configurations

set -e

SCRIPT_DIR="$(dirname "$0")"
EXAMPLES_DIR="$SCRIPT_DIR/../examples"
echo "🚀 Quick Symmetry Test"
echo "=============================="
echo "Testing in directory: $EXAMPLES_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to compare threat counts from JSON files
compare_threat_counts() {
    local file1="$1"
    local file2="$2"
    local test_name="$3"

    echo -e "\n=== $test_name ==="

    # Extract threat counts using jq
    local count1=$(jq -r '(.threats // [] | length)' "$file1" 2>/dev/null || echo "0")
    local count2=$(jq -r '(.threats // [] | length)' "$file2" 2>/dev/null || echo "0")

    # Also try alternative structure
    if [ "$count1" = "0" ]; then
        count1=$(jq -r '(.semgrep_threats // [] | length) + (.llm_threats // [] | length)' "$file1" 2>/dev/null || echo "0")
    fi
    if [ "$count2" = "0" ]; then
        count2=$(jq -r '(.semgrep_threats // [] | length) + (.llm_threats // [] | length)' "$file2" 2>/dev/null || echo "0")
    fi

    echo "MCP result threats: $count1"
    echo "CLI result threats: $count2"

    if [ "$count1" = "$count2" ]; then
        echo -e "${GREEN}✅ $test_name PASSED - Threat counts match: $count1${NC}"
        return 0
    else
        echo -e "${RED}❌ $test_name FAILED - Threat count mismatch: MCP=$count1, CLI=$count2${NC}"
        return 1
    fi
}

# Test file symmetry
test_file_symmetry() {
    local file_path="$1"
    local file_name=$(basename "$file_path")

    echo -e "\n🔍 Testing file symmetry for: $file_name"

    # Clean up any existing results
    rm -f "$EXAMPLES_DIR/.adversary.json"

    # Run MCP scan_file (results saved to .adversary.json)
    echo "Running MCP adv_scan_file..."
    adversary-mcp-cli scan "$file_path" --output-format json --no-llm --use-semgrep --no-validation --severity medium >/dev/null 2>&1

    # Copy MCP result for comparison
    local mcp_result="$EXAMPLES_DIR/.adversary_mcp.json"
    cp "$EXAMPLES_DIR/.adversary.json" "$mcp_result"

    # Clean up for CLI test
    rm -f "$EXAMPLES_DIR/.adversary.json"

    # Run CLI scan (results saved to .adversary.json)
    echo "Running CLI scan..."
    adversary-mcp-cli scan "$file_path" --output-format json --no-llm --use-semgrep --no-validation --severity medium >/dev/null 2>&1

    # Compare the JSON result files
    local cli_result="$EXAMPLES_DIR/.adversary.json"

    if [ -f "$mcp_result" ] && [ -f "$cli_result" ]; then
        compare_threat_counts "$mcp_result" "$cli_result" "File Symmetry: $file_name"
        local result=$?

        # Clean up
        rm -f "$mcp_result" "$cli_result"
        return $result
    else
        echo -e "${RED}❌ Missing result files${NC}"
        return 1
    fi
}

# Test folder symmetry
test_folder_symmetry() {
    local folder_path="$1"
    local folder_name=$(basename "$folder_path")

    echo -e "\n📁 Testing folder symmetry for: $folder_name"

    # Clean up any existing results
    rm -f "$EXAMPLES_DIR/.adversary.json"

    # Run MCP scan_folder (results saved to .adversary.json)
    echo "Running MCP adv_scan_folder..."
    adversary-mcp-cli scan "$folder_path" --output-format json --no-llm --use-semgrep --no-validation --severity medium >/dev/null 2>&1

    # Copy MCP result for comparison
    local mcp_result="$EXAMPLES_DIR/.adversary_mcp_folder.json"
    cp "$EXAMPLES_DIR/.adversary.json" "$mcp_result"

    # Clean up for CLI test
    rm -f "$EXAMPLES_DIR/.adversary.json"

    # Run CLI scan (results saved to .adversary.json)
    echo "Running CLI scan..."
    adversary-mcp-cli scan "$folder_path" --output-format json --no-llm --use-semgrep --no-validation --severity medium >/dev/null 2>&1

    # Compare the JSON result files
    local cli_result="$EXAMPLES_DIR/.adversary.json"

    if [ -f "$mcp_result" ] && [ -f "$cli_result" ]; then
        compare_threat_counts "$mcp_result" "$cli_result" "Folder Symmetry: $folder_name"
        local result=$?

        # Clean up
        rm -f "$mcp_result" "$cli_result"
        return $result
    else
        echo -e "${RED}❌ Missing result files${NC}"
        return 1
    fi
}

# Main test execution
main() {
    local overall_success=true

    # Test one individual file
    echo -e "\n${YELLOW}Testing individual file...${NC}"
    if ! test_file_symmetry "$EXAMPLES_DIR/vulnerable_python.py"; then
        overall_success=false
    fi

    # Test folder scanning on examples directory
    echo -e "\n${YELLOW}Testing folder scanning...${NC}"
    if ! test_folder_symmetry "$EXAMPLES_DIR"; then
        overall_success=false
    fi

    # Final result
    echo -e "\n=============================="
    if [ "$overall_success" = true ]; then
        echo -e "${GREEN}🎉 SYMMETRY TESTS PASSED!${NC}"
        echo -e "${GREEN}✅ MCP tools and CLI produce identical results${NC}"
        exit 0
    else
        echo -e "${RED}💥 SYMMETRY TESTS FAILED!${NC}"
        echo -e "${RED}❌ MCP tools and CLI produce different results${NC}"
        exit 1
    fi
}

# Run the tests
main "$@"
