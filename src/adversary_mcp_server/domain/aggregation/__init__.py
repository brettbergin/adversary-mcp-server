"""Threat aggregation and deduplication logic.

This module handles the intelligent combination of threats from multiple
scanning engines, providing deduplication and prioritization logic.
"""

from .threat_aggregator import ThreatAggregator

__all__ = ["ThreatAggregator"]
