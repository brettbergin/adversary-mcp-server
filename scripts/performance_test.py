#!/usr/bin/env python3
"""Performance testing script for SQLAlchemy telemetry queries."""

import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import func

from adversary_mcp_server.database.models import (
    AdversaryDatabase,
    CacheOperationMetric,
    CLICommandExecution,
    MCPToolExecution,
    ScanEngineExecution,
    SystemHealth,
    ThreatFinding,
)
from adversary_mcp_server.telemetry.service import TelemetryService


class PerformanceTester:
    """Performance testing suite for SQLAlchemy telemetry queries."""

    def __init__(self, db_path: Path = None):
        self.db_path = (
            db_path
            or Path.home() / ".local/share/adversary-mcp-server/cache/adversary.db"
        )
        self.db = AdversaryDatabase(self.db_path)
        self.service = TelemetryService(self.db)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.db.close()

    def time_function(self, func: Callable, runs: int = 5) -> dict[str, Any]:
        """Time a function execution multiple times and return statistics."""
        times = []
        for _ in range(runs):
            start_time = time.time()
            result = func()
            end_time = time.time()
            times.append(end_time - start_time)

        return {
            "avg": statistics.mean(times),
            "min": min(times),
            "max": max(times),
            "median": statistics.median(times),
            "stdev": statistics.stdev(times) if len(times) > 1 else 0,
            "result_sample": str(result)[:100] if result else "None",
        }

    def test_dashboard_queries(self) -> dict[str, Any]:
        """Test dashboard query performance."""
        print("🔍 Testing Dashboard Query Performance")

        results = {}

        # Test different time ranges
        time_ranges = [1, 24, 168, 720]  # 1h, 1d, 1w, 1m
        for hours in time_ranges:

            def get_dashboard_data_for_hours(h=hours):
                return self.service.get_dashboard_data(h)

            stats = self.time_function(get_dashboard_data_for_hours, runs=3)
            results[f"dashboard_{hours}h"] = stats
            print(f"  Dashboard data ({hours}h): {stats['avg']:.4f}s avg")

        return results

    def test_individual_table_queries(self) -> dict[str, Any]:
        """Test individual table query performance."""
        print("\n📊 Testing Individual Table Queries")

        results = {}

        with self.service.get_repository() as repo:
            queries = {
                "mcp_tool_count": lambda: repo.session.query(MCPToolExecution).count(),
                "cli_command_count": lambda: repo.session.query(
                    CLICommandExecution
                ).count(),
                "cache_operation_count": lambda: repo.session.query(
                    CacheOperationMetric
                ).count(),
                "scan_execution_count": lambda: repo.session.query(
                    ScanEngineExecution
                ).count(),
                "threat_finding_count": lambda: repo.session.query(
                    ThreatFinding
                ).count(),
                "system_health_count": lambda: repo.session.query(SystemHealth).count(),
            }

            for query_name, query_func in queries.items():
                stats = self.time_function(query_func, runs=10)
                results[query_name] = stats
                print(
                    f"  {query_name}: {stats['avg']:.4f}s avg (result: {stats['result_sample']})"
                )

        return results

    def test_aggregation_queries(self) -> dict[str, Any]:
        """Test complex aggregation query performance."""
        print("\n📈 Testing Aggregation Queries")

        results = {}

        with self.service.get_repository() as repo:
            # MCP tool aggregation
            def mcp_agg():
                return (
                    repo.session.query(
                        MCPToolExecution.tool_name,
                        func.count(MCPToolExecution.id).label("executions"),
                        func.sum(MCPToolExecution.findings_count).label(
                            "total_findings"
                        ),
                        func.avg(MCPToolExecution.execution_start).label(
                            "avg_start_time"
                        ),
                    )
                    .group_by(MCPToolExecution.tool_name)
                    .all()
                )

            # CLI command aggregation
            def cli_agg():
                return (
                    repo.session.query(
                        CLICommandExecution.command_name,
                        func.count(CLICommandExecution.id).label("executions"),
                        func.sum(CLICommandExecution.findings_count).label(
                            "total_findings"
                        ),
                        func.avg(CLICommandExecution.exit_code).label("avg_exit_code"),
                    )
                    .group_by(CLICommandExecution.command_name)
                    .all()
                )

            # Cache performance aggregation
            def cache_agg():
                return (
                    repo.session.query(
                        CacheOperationMetric.cache_name,
                        func.count(CacheOperationMetric.id).label("operations"),
                        func.avg(CacheOperationMetric.access_time_ms).label(
                            "avg_access_time"
                        ),
                        func.sum(CacheOperationMetric.size_bytes).label("total_size"),
                    )
                    .group_by(CacheOperationMetric.cache_name)
                    .all()
                )

            aggregations = {
                "mcp_tool_aggregation": mcp_agg,
                "cli_command_aggregation": cli_agg,
                "cache_performance_aggregation": cache_agg,
            }

            for agg_name, agg_func in aggregations.items():
                stats = self.time_function(agg_func, runs=5)
                results[agg_name] = stats
                print(f"  {agg_name}: {stats['avg']:.4f}s avg")

        return results

    def test_bulk_operations(self) -> dict[str, Any]:
        """Test bulk insert/update performance."""
        print("\n🚀 Testing Bulk Operations")

        results = {}

        with self.service.get_repository() as repo:
            # Test bulk cache operation inserts
            def bulk_cache_inserts(count: int):
                for i in range(count):
                    repo.track_cache_operation(
                        operation_type="performance_test",
                        cache_name="bulk_test",
                        key_hash=f"bulk_key_{i}",
                        access_time_ms=0.1,
                        size_bytes=1024,
                    )

            # Test different bulk sizes
            bulk_sizes = [10, 50, 100]
            for size in bulk_sizes:
                stats = self.time_function(lambda s=size: bulk_cache_inserts(s), runs=3)
                results[f"bulk_cache_{size}"] = stats
                per_op = (stats["avg"] / size) * 1000  # ms per operation
                print(
                    f"  Bulk cache insert ({size} ops): {stats['avg']:.4f}s total, {per_op:.2f}ms per op"
                )

        return results

    def test_database_size_impact(self) -> dict[str, Any]:
        """Test how database size impacts query performance."""
        print("\n💾 Testing Database Size Impact")

        results = {}

        # Get current database size
        db_size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
        db_size_mb = db_size_bytes / (1024 * 1024)

        print(f"  Database size: {db_size_mb:.2f} MB")

        # Count records in each table
        with self.service.get_repository() as repo:
            record_counts = {
                "mcp_tool_executions": repo.session.query(MCPToolExecution).count(),
                "cli_command_executions": repo.session.query(
                    CLICommandExecution
                ).count(),
                "cache_operations": repo.session.query(CacheOperationMetric).count(),
                "scan_executions": repo.session.query(ScanEngineExecution).count(),
                "threat_findings": repo.session.query(ThreatFinding).count(),
                "system_health_snapshots": repo.session.query(SystemHealth).count(),
            }

            total_records = sum(record_counts.values())
            print(f"  Total records: {total_records}")
            for table, count in record_counts.items():
                print(f"    {table}: {count}")

        # Test query performance relative to database size
        dashboard_stats = self.time_function(
            lambda: self.service.get_dashboard_data(24), runs=5
        )

        results["database_metrics"] = {
            "size_mb": db_size_mb,
            "total_records": total_records,
            "record_counts": record_counts,
            "dashboard_query_time": dashboard_stats["avg"],
            "records_per_ms": (
                total_records / (dashboard_stats["avg"] * 1000)
                if dashboard_stats["avg"] > 0
                else 0
            ),
        }

        print(f"  Dashboard query performance: {dashboard_stats['avg']:.4f}s")
        print(
            f"  Processing rate: {results['database_metrics']['records_per_ms']:.0f} records/ms"
        )

        return results

    def analyze_query_patterns(self) -> dict[str, Any]:
        """Analyze query patterns and identify optimization opportunities."""
        print("\n🎯 Analyzing Query Patterns")

        results = {}

        with self.service.get_repository() as repo:
            # Test different query patterns

            # Pattern 1: SELECT with WHERE clause
            time_filtered = self.time_function(
                lambda: repo.session.query(CLICommandExecution)
                .filter(CLICommandExecution.execution_start > time.time() - 3600)
                .count(),
                runs=10,
            )

            # Pattern 2: COUNT with GROUP BY
            group_by_count = self.time_function(
                lambda: repo.session.query(
                    CacheOperationMetric.cache_name, func.count(CacheOperationMetric.id)
                )
                .group_by(CacheOperationMetric.cache_name)
                .all(),
                runs=10,
            )

            # Pattern 3: Complex JOIN (if we had foreign keys)
            # For now, just test subqueries
            subquery_test = self.time_function(
                lambda: repo.session.query(MCPToolExecution)
                .filter(MCPToolExecution.findings_count > 0)
                .count(),
                runs=10,
            )

            results["query_patterns"] = {
                "time_filtered_query": time_filtered,
                "group_by_aggregation": group_by_count,
                "filtered_subquery": subquery_test,
            }

            for pattern, stats in results["query_patterns"].items():
                print(f"  {pattern}: {stats['avg']:.4f}s avg")

        return results

    def generate_performance_report(self) -> dict[str, Any]:
        """Run comprehensive performance tests and generate report."""
        print("🔍 SQLAlchemy Performance Analysis Report")
        print("=" * 60)

        report = {
            "test_metadata": {
                "database_path": str(self.db_path),
                "test_timestamp": time.time(),
                "test_date": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            }
        }

        # Run all test suites
        test_suites = [
            ("dashboard_queries", self.test_dashboard_queries),
            ("table_queries", self.test_individual_table_queries),
            ("aggregation_queries", self.test_aggregation_queries),
            ("bulk_operations", self.test_bulk_operations),
            ("database_size_impact", self.test_database_size_impact),
            ("query_patterns", self.analyze_query_patterns),
        ]

        for suite_name, suite_func in test_suites:
            try:
                report[suite_name] = suite_func()
            except Exception as e:
                print(f"❌ Error in {suite_name}: {e}")
                report[suite_name] = {"error": str(e)}

        # Generate recommendations
        report["recommendations"] = self.generate_optimization_recommendations(report)

        print("\n✅ Performance testing completed")
        return report

    def generate_optimization_recommendations(
        self, report: dict[str, Any]
    ) -> list[str]:
        """Generate optimization recommendations based on test results."""
        recommendations = []

        # Check dashboard query performance
        dashboard_results = report.get("dashboard_queries", {})
        if dashboard_results:
            avg_times = [
                stats.get("avg", 0)
                for stats in dashboard_results.values()
                if isinstance(stats, dict)
            ]
            if avg_times and max(avg_times) > 0.1:  # > 100ms
                recommendations.append(
                    "Consider adding database indexes on frequently queried timestamp columns (execution_start, timestamp)"
                )

        # Check aggregation performance
        agg_results = report.get("aggregation_queries", {})
        if agg_results:
            avg_times = [
                stats.get("avg", 0)
                for stats in agg_results.values()
                if isinstance(stats, dict)
            ]
            if avg_times and max(avg_times) > 0.05:  # > 50ms
                recommendations.append(
                    "Consider adding composite indexes on GROUP BY columns (tool_name, command_name, cache_name)"
                )

        # Check bulk operation performance
        bulk_results = report.get("bulk_operations", {})
        if bulk_results:
            avg_times = [
                stats.get("avg", 0)
                for stats in bulk_results.values()
                if isinstance(stats, dict)
            ]
            if avg_times and max(avg_times) > 0.1:
                recommendations.append(
                    "Consider using SQLAlchemy bulk_insert_mappings for better bulk insert performance"
                )

        # Check database size impact
        db_metrics = report.get("database_size_impact", {}).get("database_metrics", {})
        if db_metrics.get("records_per_ms", 0) < 100:
            recommendations.append(
                "Query processing rate is low - consider database optimization or query restructuring"
            )

        # General recommendations
        recommendations.extend(
            [
                "Consider implementing connection pooling for high-concurrency scenarios",
                "Monitor query execution plans using EXPLAIN QUERY PLAN for complex queries",
                "Implement query result caching for frequently accessed dashboard data",
                "Consider database maintenance operations (VACUUM, ANALYZE) for SQLite optimization",
            ]
        )

        return recommendations


def main():
    """Run performance tests and print results."""
    with PerformanceTester() as tester:
        report = tester.generate_performance_report()

        print("\n📋 Performance Test Summary")
        print("=" * 40)

        # Print key metrics
        db_metrics = report.get("database_size_impact", {}).get("database_metrics", {})
        if db_metrics:
            print(f"Database size: {db_metrics.get('size_mb', 0):.2f} MB")
            print(f"Total records: {db_metrics.get('total_records', 0)}")
            print(
                f"Processing rate: {db_metrics.get('records_per_ms', 0):.0f} records/ms"
            )

        # Print recommendations
        recommendations = report.get("recommendations", [])
        if recommendations:
            print(f"\n🎯 Optimization Recommendations ({len(recommendations)}):")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")


if __name__ == "__main__":
    main()
