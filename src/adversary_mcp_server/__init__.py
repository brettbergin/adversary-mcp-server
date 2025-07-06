"""Adversary MCP Server - Security-focused Model Context Protocol server."""

__version__ = "0.1.0"
__author__ = "Brett Bergin"
__email__ = "brettberginbc@yahoo.com"
__description__ = (
    "MCP server for adversarial security analysis and vulnerability detection"
)

from .ast_scanner import ASTScanner
from .exploit_generator import ExploitGenerator
from .server import AdversaryMCPServer
from .threat_engine import ThreatEngine

__all__ = [
    "AdversaryMCPServer",
    "ThreatEngine",
    "ASTScanner",
    "ExploitGenerator",
]
