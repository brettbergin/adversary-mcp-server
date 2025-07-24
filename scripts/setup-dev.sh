#!/bin/bash
# Setup script for adversary-mcp-server development environment

set -e  # Exit on any error

echo "🚀 Setting up adversary-mcp-server development environment..."

# Check if we're in a virtual environment
if [[ -z "$VIRTUAL_ENV" && ! -d ".venv" ]]; then
    echo "⚠️  No virtual environment detected. Creating one..."
    python3 -m venv .venv
    echo "✅ Virtual environment created. Please activate it with:"
    echo "   source .venv/bin/activate"
    echo "   Then run this script again."
    exit 0
elif [[ -d ".venv" && -z "$VIRTUAL_ENV" ]]; then
    echo "📦 Activating virtual environment..."
    source .venv/bin/activate
fi

# Check if uv is available
if command -v uv &> /dev/null; then
    echo "⚡ Using uv for faster installation..."
    make dev-setup-uv
else
    echo "📦 Using pip for installation..."
    make dev-setup
fi

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "🔧 Available commands:"
echo "  make test           - Run tests with coverage"
echo "  make lint           - Run linting tools"
echo "  make format         - Format code"
echo "  make security-scan  - Run security scans"
echo "  make pre-commit     - Run pre-commit hooks"
echo "  make help           - Show all available commands"
echo ""
echo "🚨 Pre-commit hooks are now installed and will run automatically on commit"
echo "   To skip hooks for a commit, use: git commit --no-verify"
echo ""
echo "Happy coding! 🎯"
