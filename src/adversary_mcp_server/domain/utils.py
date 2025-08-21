"""Utility functions for domain operations."""


def merge_scanner_names(scanner1: str, scanner2: str) -> str:
    """
    Merge scanner names without duplication.

    Args:
        scanner1: First scanner name (e.g., "semgrep" or "semgrep+llm")
        scanner2: Second scanner name (e.g., "semgrep" or "llm")

    Returns:
        Merged scanner name with unique scanners (e.g., "llm+semgrep")
    """
    if scanner1 == scanner2:
        return scanner1

    # Split both scanner names and create a set to avoid duplicates
    scanners1 = set(scanner1.split("+"))
    scanners2 = set(scanner2.split("+"))

    # Merge the sets and sort for consistent output
    merged_scanners = scanners1 | scanners2

    return "+".join(sorted(merged_scanners))
