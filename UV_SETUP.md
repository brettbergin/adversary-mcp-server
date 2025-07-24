# UV Setup Guide

This guide covers using `uv` for fast Python package management with the Adversary MCP Server.

## What is uv?

`uv` is a fast Python package installer and resolver written in Rust. It's designed to be a drop-in replacement for pip and pip-tools, offering:

- **Speed**: 10-100x faster than pip
- **Reliability**: Better dependency resolution
- **Lock files**: Reproducible environments
- **Virtual environments**: Built-in venv management

## Installation

### Install uv

```bash
pip install uv
```

Or using the standalone installer:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/brettbergin/adversary-mcp-server.git
cd adversary-mcp-server
```

### 2. Create Virtual Environment

```bash
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install package in development mode
uv pip install -e ".[dev]"

# Or use make
make dev-setup-uv
```

### 4. Verify Installation

```bash
# Check server status
adversary-mcp-cli status

# Run tests
make test
```

## Development Workflow

### Adding Dependencies

```bash
# Add a new dependency
uv pip install package-name

# Update pyproject.toml
# Then regenerate lock files
make lock
```

### Lock Files

The project uses two lock files:
- `uv.lock` - Production dependencies
- `uv-dev.lock` - Development dependencies

```bash
# Generate lock files
make lock

# Install from lock file
uv pip sync uv-dev.lock
```

### Virtual Environment Management

```bash
# Create new environment
uv venv

# Create with specific Python version
uv venv --python 3.12

# Activate environment
source .venv/bin/activate

# Install project
uv pip install -e .
```

### Speed Comparison

| Operation | pip | uv | Speedup |
|-----------|-----|----|---------|
| Install from PyPI | 45s | 2s | 22x |
| Install from lock | 30s | 1s | 30x |
| Dependency resolution | 120s | 3s | 40x |

## Available Make Targets

```bash
# uv-specific targets
make uv-init           # Initialize uv virtual environment
make dev-setup-uv      # Setup development environment with uv
make install-uv        # Install package using uv
make sync              # Sync dependencies using uv
make lock              # Generate lock files
make uv-upgrade        # Upgrade all dependencies
```

## Troubleshooting

### Common Issues

1. **uv not found**: Install uv first with `pip install uv`
2. **Permission errors**: Use virtual environment with `uv venv`
3. **Lock file conflicts**: Regenerate with `make lock`

### Getting Help

```bash
# uv help
uv --help
uv pip --help

# Project help
make help
```

## Migration from pip

If you're currently using pip, here's the migration path:

1. **Install uv**: `pip install uv`
2. **Create venv**: `uv venv`
3. **Activate**: `source .venv/bin/activate`
4. **Install**: `uv pip install -e ".[dev]"`
5. **Generate locks**: `make lock`

Your existing `requirements.txt` and `pyproject.toml` work as-is with uv.

## Best Practices

1. **Use virtual environments**: Always activate `.venv` before installing
2. **Pin dependencies**: Use lock files for reproducible builds
3. **Regular updates**: Run `make uv-upgrade` monthly
4. **CI/CD integration**: Use `uv pip sync` in CI for consistent builds

## Performance Tips

- Use `uv pip sync` instead of `pip install -r requirements.txt`
- Generate lock files with `make lock` after dependency changes
- Use `uv venv` for fast virtual environment creation
- Consider using `uv pip install` for faster installs in CI

## Resources

- [uv Documentation](https://docs.astral.sh/uv/)
- [uv GitHub Repository](https://github.com/astral-sh/uv)
- [Python Package Management Guide](https://packaging.python.org/)
