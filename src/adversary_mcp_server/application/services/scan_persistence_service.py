"""Application service for persisting scan results using Clean Architecture."""

import logging
import os
from enum import Enum
from pathlib import Path
from typing import Any

from adversary_mcp_server.application.formatters.domain_result_formatter import (
    DomainScanResultFormatter,
)
from adversary_mcp_server.domain.entities.scan_result import ScanResult

logger = logging.getLogger(__name__)


class OutputFormat(Enum):
    """Supported output formats for scan result persistence."""

    JSON = "json"
    MARKDOWN = "md"
    CSV = "csv"

    @classmethod
    def from_string(cls, format_str: str) -> "OutputFormat":
        """Create OutputFormat from string, with validation."""
        format_str = format_str.lower().strip()

        # Handle common variations
        format_mapping = {
            "json": cls.JSON,
            "markdown": cls.MARKDOWN,
            "md": cls.MARKDOWN,
            "csv": cls.CSV,
        }

        if format_str in format_mapping:
            return format_mapping[format_str]

        raise ValueError(
            f"Unsupported output format: {format_str}. Supported: {list(format_mapping.keys())}"
        )

    def get_file_extension(self) -> str:
        """Get the appropriate file extension for this format."""
        return f".{self.value}"


class ScanResultPersistenceService:
    """
    Application service for persisting scan results to files.

    This service:
    - Determines appropriate file placement based on scan context
    - Supports multiple output formats (JSON, Markdown, CSV)
    - Handles file system operations safely
    - Follows Clean Architecture principles
    - Provides consistent persistence behavior across CLI and MCP tools
    """

    def __init__(self, include_metadata: bool = True, include_exploits: bool = False):
        """
        Initialize the persistence service.

        Args:
            include_metadata: Whether to include detailed metadata in output
            include_exploits: Whether to include exploit examples (security consideration)
        """
        self.formatter = DomainScanResultFormatter(
            include_metadata=include_metadata, include_exploits=include_exploits
        )
        self.logger = logger

    async def persist_scan_result(
        self,
        result: ScanResult,
        output_format: OutputFormat | str = OutputFormat.JSON,
        custom_output_path: str | None = None,
    ) -> str:
        """
        Persist scan result to an appropriate file location.

        Args:
            result: The scan result to persist
            output_format: Output format (JSON, Markdown, or CSV)
            custom_output_path: Optional custom output path (overrides automatic placement)

        Returns:
            str: Path to the created file

        Raises:
            ValueError: If output format is invalid
            PermissionError: If unable to write to target location
            OSError: If file system operations fail
        """
        # Normalize output format
        if isinstance(output_format, str):
            output_format = OutputFormat.from_string(output_format)

        # Determine output file path
        if custom_output_path:
            output_path = Path(custom_output_path)
        else:
            output_path = self._determine_output_path(result, output_format)

        # Format the content
        formatted_content = self._format_content(result, output_format)

        # Write to file
        await self._write_file(output_path, formatted_content)

        self.logger.info(
            f"Scan result persisted to {output_path} (format: {output_format.value})"
        )

        return str(output_path)

    async def persist_multiple_formats(
        self,
        result: ScanResult,
        formats: list[OutputFormat | str],
        base_directory: str | None = None,
    ) -> dict[str, str]:
        """
        Persist scan result in multiple formats.

        Args:
            result: The scan result to persist
            formats: List of output formats to generate
            base_directory: Optional base directory (overrides automatic placement)

        Returns:
            dict: Mapping of format -> file path for each generated file
        """
        results = {}

        for format_spec in formats:
            if isinstance(format_spec, str):
                format_obj = OutputFormat.from_string(format_spec)
            else:
                format_obj = format_spec

            # Use base directory if provided
            custom_path = None
            if base_directory:
                filename = f"adversary{format_obj.get_file_extension()}"
                custom_path = str(Path(base_directory) / filename)

            file_path = await self.persist_scan_result(result, format_obj, custom_path)
            results[format_obj.value] = file_path

        return results

    def _determine_output_path(
        self, result: ScanResult, output_format: OutputFormat
    ) -> Path:
        """
        Determine the appropriate output file path based on scan context.

        File placement logic:
        - File scans: Place .adversary.* in same directory as scanned file
        - Directory scans: Place .adversary.* in the scanned directory
        - Code scans: Place .adversary.* in current working directory
        """
        scan_type = result.request.context.metadata.scan_type
        target_path = result.request.context.target_path
        extension = output_format.get_file_extension()

        if scan_type == "file":
            # Place in same directory as the scanned file
            file_path = Path(str(target_path))
            if file_path.is_file():
                output_dir = file_path.parent
            else:
                # Handle case where file might not exist
                output_dir = (
                    file_path.parent if file_path.parent.exists() else Path.cwd()
                )
        elif scan_type == "directory":
            # Place in the scanned directory
            dir_path = Path(str(target_path))
            output_dir = dir_path if dir_path.is_dir() else Path.cwd()
        elif scan_type == "code":
            # Place in current working directory
            output_dir = Path.cwd()
        else:
            # Fallback to current directory
            output_dir = Path.cwd()
            self.logger.warning(
                f"Unknown scan type '{scan_type}', using current directory"
            )

        # Create the output file path
        output_path = output_dir / f"adversary{extension}"

        # Handle filename conflicts by adding incremental suffix
        if output_path.exists():
            counter = 1
            base_name = f"adversary-{counter}{extension}"
            while (output_dir / base_name).exists():
                counter += 1
                base_name = f"adversary-{counter}{extension}"
            output_path = output_dir / base_name

        return output_path

    def _format_content(self, result: ScanResult, output_format: OutputFormat) -> str:
        """Format scan result content according to the specified format."""
        if output_format == OutputFormat.JSON:
            return self.formatter.format_json(result)
        elif output_format == OutputFormat.MARKDOWN:
            return self.formatter.format_markdown(result)
        elif output_format == OutputFormat.CSV:
            return self.formatter.format_csv(result)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    async def _write_file(self, file_path: Path, content: str) -> None:
        """
        Write content to file with proper error handling.

        Args:
            file_path: Path to write to
            content: Content to write

        Raises:
            PermissionError: If unable to write to target location
            OSError: If file system operations fail
        """
        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Write file atomically (write to temp file, then move)
            temp_path = file_path.with_suffix(f"{file_path.suffix}.tmp")

            # Write content with proper encoding
            temp_path.write_text(content, encoding="utf-8")

            # Atomic move
            temp_path.replace(file_path)

            self.logger.debug(f"Successfully wrote {len(content)} bytes to {file_path}")

        except PermissionError as e:
            self.logger.error(f"Permission denied writing to {file_path}: {e}")
            raise
        except OSError as e:
            self.logger.error(f"File system error writing to {file_path}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error writing to {file_path}: {e}")
            # Clean up temp file if it exists
            temp_path = file_path.with_suffix(f"{file_path.suffix}.tmp")
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass  # Best effort cleanup
            raise

    def get_supported_formats(self) -> list[str]:
        """Get list of supported output formats."""
        return [fmt.value for fmt in OutputFormat]

    def validate_output_path(self, path: str) -> bool:
        """
        Validate that an output path is writable.

        Args:
            path: Path to validate

        Returns:
            bool: True if path is writable, False otherwise
        """
        try:
            target_path = Path(path)

            # Check if parent directory exists and is writable
            if target_path.parent.exists():
                return target_path.parent.is_dir() and os.access(
                    target_path.parent, os.W_OK
                )
            else:
                # Check if we can create the parent directory
                try:
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    return True
                except (PermissionError, OSError):
                    return False

        except Exception:
            return False

    def get_placement_info(self, result: ScanResult) -> dict[str, Any]:
        """
        Get information about where files would be placed for this scan result.

        Args:
            result: Scan result to analyze

        Returns:
            dict: Information about file placement strategy
        """
        scan_type = result.request.context.metadata.scan_type
        target_path = result.request.context.target_path

        placement_info = {
            "scan_type": scan_type,
            "target_path": str(target_path),
            "placement_strategy": self._get_placement_strategy_description(scan_type),
            "output_paths": {},
        }

        # Generate example paths for each format
        for format_enum in OutputFormat:
            try:
                example_path = self._determine_output_path(result, format_enum)
                placement_info["output_paths"][format_enum.value] = str(example_path)
            except Exception as e:
                placement_info["output_paths"][format_enum.value] = f"Error: {e}"

        return placement_info

    def _get_placement_strategy_description(self, scan_type: str) -> str:
        """Get human-readable description of file placement strategy."""
        strategies = {
            "file": "Files placed in same directory as scanned file",
            "directory": "Files placed in the scanned directory",
            "code": "Files placed in current working directory",
        }
        return strategies.get(scan_type, "Files placed in current working directory")
