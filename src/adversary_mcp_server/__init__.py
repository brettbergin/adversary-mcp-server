"""Adversary MCP Server - Security vulnerability scanning and detection."""

import re
import sys
from importlib.metadata import version
from pathlib import Path


def _get_default_version() -> str:
    """Get the default version from pyproject.toml at module load time."""
    try:
        # Get the project root (go up from src/adversary_mcp_server)
        project_root = Path(__file__).parent.parent.parent
        pyproject_path = project_root / "pyproject.toml"

        if pyproject_path.exists():
            # Use tomllib for Python 3.11+ or simple parsing for older versions
            if sys.version_info >= (3, 11) or sys.version_info >= (3, 12):
                import tomllib

                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                    return pyproject_data.get("project", {}).get("version", "0.7.4")
            else:
                # Simple regex parsing for older Python versions
                with open(pyproject_path) as f:
                    content = f.read()
                    match = re.search(
                        r'^version\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE
                    )
                    if match:
                        return match.group(1)
        return "0.7.4"
    except Exception:
        return "0.7.4"


# Default fallback version - automatically synced from pyproject.toml
DEFAULT_VERSION = _get_default_version()


def _read_version_from_pyproject() -> str:
    """Read version from pyproject.toml file."""
    try:
        # Get the project root (go up from src/adversary_mcp_server)
        project_root = Path(__file__).parent.parent.parent
        pyproject_path = project_root / "pyproject.toml"

        if pyproject_path.exists():
            # Use tomllib for Python 3.11+ or simple parsing for older versions
            if sys.version_info >= (3, 11) or sys.version_info >= (3, 12):
                import tomllib

                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                    return pyproject_data.get("project", {}).get("version", "unknown")
            else:
                # Simple regex parsing for older Python versions
                with open(pyproject_path) as f:
                    content = f.read()

                    match = re.search(
                        r'^version\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE
                    )
                    if match:
                        return match.group(1)
                    return "unknown"
    except Exception:
        pass

    # Final fallback to constant
    return DEFAULT_VERSION


def get_version() -> str:
    """Get the current version of the adversary-mcp-server package."""
    try:
        return version("adversary-mcp-server")
    except Exception:
        # Fallback - read from pyproject.toml using standard library
        try:
            return _read_version_from_pyproject()
        except Exception:
            # Final fallback to constant if all methods fail
            return DEFAULT_VERSION


__version__ = get_version()
__author__ = "Brett Bergin"
__email__ = "brettberginbc@yahoo.com"
__description__ = "MCP server for security vulnerability scanning and detection"

from .scanner.exploit_generator import ExploitGenerator
from .server import AdversaryMCPServer

__all__ = [
    "AdversaryMCPServer",
    "ExploitGenerator",
]
