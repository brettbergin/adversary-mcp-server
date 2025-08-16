#!/bin/bash
# Install adversary-mcp-server as an MCP server for Claude Code
# This script configures Claude Code to use the adversary-mcp-server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on macOS (Claude Code is primarily macOS)
if [[ "$OSTYPE" != "darwin"* ]]; then
    print_warning "This script is designed for macOS. Claude Code MCP configuration may differ on other platforms."
fi

# Get the current directory (project root)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
print_status "Project root: $PROJECT_ROOT"

# Check if we're in a virtual environment and activate it
if [[ -f "$PROJECT_ROOT/.venv/bin/activate" ]]; then
    print_status "Activating virtual environment..."
    source "$PROJECT_ROOT/.venv/bin/activate"
else
    print_warning "No virtual environment found at $PROJECT_ROOT/.venv"
    print_status "Creating virtual environment with uv..."
    cd "$PROJECT_ROOT"
    uv venv
    source .venv/bin/activate
fi

# Install the package in development mode
print_status "Installing adversary-mcp-server in development mode..."
cd "$PROJECT_ROOT"
uv pip install -e ".[dev]"

# Get Python path from the virtual environment
PYTHON_PATH="$PROJECT_ROOT/.venv/bin/python"
if [[ ! -f "$PYTHON_PATH" ]]; then
    print_error "Python not found at expected path: $PYTHON_PATH"
    exit 1
fi

print_status "Using Python: $PYTHON_PATH"

# Configure Claude Code MCP using claude mcp add-json command
print_status "Configuring Claude Code MCP settings..."

# Remove any existing adversary server configuration
claude mcp remove adversary 2>/dev/null || true

# Add the adversary MCP server using claude mcp add-json (Clean Architecture)
MCP_CONFIG="{
  \"command\": \"uv\",
  \"args\": [
    \"run\",
    \"--directory\",
    \"$PROJECT_ROOT\",
    \"adversary-mcp-server\"
  ]
}"

if claude mcp add-json adversary "$MCP_CONFIG"; then
    print_success "MCP server configuration added successfully"
else
    print_error "Failed to add MCP server configuration"
    exit 1
fi


# Test the MCP server (Clean Architecture)
print_status "Testing MCP server installation..."
if "$PYTHON_PATH" -c "from adversary_mcp_server.application.mcp_server import CleanMCPServer" 2>/dev/null; then
    print_success "Clean Architecture MCP server imports correctly"
else
    print_warning "Clean Architecture MCP server import test failed"
fi

# Test CLI installation
print_status "Testing CLI installation..."
if "$PROJECT_ROOT/.venv/bin/adversary-mcp-cli" --version > /dev/null 2>&1; then
    CLI_VERSION=$("$PROJECT_ROOT/.venv/bin/adversary-mcp-cli" --version)
    print_success "CLI installed successfully: $CLI_VERSION"
else
    print_warning "CLI test failed"
fi

print_success "Installation completed!"
print_status ""
print_status "Next steps:"
print_status "1. Restart Claude Code or reload the MCP configuration"
print_status "2. In Claude Code, you should now have access to adversary-mcp-server tools:"
print_status "   - adv_scan_code: Scan code snippets for security vulnerabilities"
print_status "   - adv_scan_file: Scan individual files"
print_status "   - adv_scan_directory: Scan entire directories"
print_status "   - adv_diff_scan: Git diff-aware scanning"
print_status "   - adv_generate_exploit: Generate educational exploit examples"
print_status ""
print_status "MCP server configured via: claude mcp add-json adversary"
print_status "Project root: $PROJECT_ROOT"
print_status "Python path: $PYTHON_PATH"
print_status ""
print_status "To test both pathways:"
print_status "• CLI: $PROJECT_ROOT/.venv/bin/adversary-mcp-cli scan [file/directory]"
print_status "• MCP: Use Claude Code with the adv_* tools"
print_status ""
print_warning "If you encounter issues, check that Claude Code can access the MCP server"
print_warning "and that the configuration file is valid JSON."
