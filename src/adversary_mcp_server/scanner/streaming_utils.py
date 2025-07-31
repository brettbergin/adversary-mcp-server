"""Streaming utilities for large file processing."""

import asyncio
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

from ..logger import get_logger

logger = get_logger("streaming_utils")


class StreamingFileReader:
    """Streaming file reader for processing large files in chunks."""

    def __init__(self, chunk_size: int = 8192):
        """Initialize streaming file reader.

        Args:
            chunk_size: Size of chunks to read in bytes
        """
        self.chunk_size = chunk_size

    async def read_file_async(self, file_path: Path) -> AsyncIterator[str]:
        """Read file asynchronously in chunks.

        Args:
            file_path: Path to file to read

        Yields:
            String chunks of the file
        """
        logger.debug(f"Starting streaming read of {file_path}")

        try:
            # Use asyncio to read file in chunks
            loop = asyncio.get_event_loop()

            def read_chunk(f, size):
                return f.read(size)

            with open(file_path, encoding="utf-8") as f:
                while True:
                    # Read chunk in thread to avoid blocking
                    chunk = await loop.run_in_executor(
                        None, read_chunk, f, self.chunk_size
                    )
                    if not chunk:
                        break
                    yield chunk

        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            raise

    def read_file_chunks(
        self, file_path: Path, max_size: int | None = None
    ) -> Iterator[str]:
        """Read file in chunks synchronously.

        Args:
            file_path: Path to file to read
            max_size: Maximum total size to read (None for unlimited)

        Yields:
            String chunks of the file
        """
        logger.debug(f"Reading file {file_path} in chunks (max_size: {max_size})")

        try:
            total_read = 0
            with open(file_path, encoding="utf-8") as f:
                while True:
                    if max_size and total_read >= max_size:
                        logger.debug(f"Reached max size limit {max_size}")
                        break

                    remaining = None
                    if max_size:
                        remaining = max_size - total_read
                        chunk_size = min(self.chunk_size, remaining)
                    else:
                        chunk_size = self.chunk_size

                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    total_read += len(chunk)
                    yield chunk

        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            raise

    async def get_file_preview(self, file_path: Path, preview_size: int = 4096) -> str:
        """Get a preview of a file for analysis.

        Args:
            file_path: Path to file
            preview_size: Size of preview in bytes

        Returns:
            Preview string
        """
        logger.debug(f"Getting {preview_size} byte preview of {file_path}")

        preview_chunks = []
        total_size = 0

        async for chunk in self.read_file_async(file_path):
            preview_chunks.append(chunk)
            total_size += len(chunk)

            if total_size >= preview_size:
                # Truncate the last chunk if needed
                excess = total_size - preview_size
                if excess > 0:
                    preview_chunks[-1] = preview_chunks[-1][:-excess]
                break

        preview = "".join(preview_chunks)
        logger.debug(f"Generated {len(preview)} character preview")
        return preview


class ChunkedProcessor:
    """Process content in chunks to avoid memory issues."""

    def __init__(self, chunk_overlap: int = 200):
        """Initialize chunked processor.

        Args:
            chunk_overlap: Number of characters to overlap between chunks
        """
        self.chunk_overlap = chunk_overlap

    def split_content_into_chunks(
        self, content: str, chunk_size: int = 8000, preserve_lines: bool = True
    ) -> list[str]:
        """Split content into overlapping chunks.

        Args:
            content: Content to split
            chunk_size: Target size of each chunk
            preserve_lines: Whether to try to break on line boundaries

        Returns:
            List of content chunks
        """
        if len(content) <= chunk_size:
            return [content]

        chunks = []
        start = 0

        while start < len(content):
            end = start + chunk_size

            # Try to break on line boundaries if requested
            if preserve_lines and end < len(content):
                # Look for a newline within the last 200 characters
                search_start = max(end - 200, start)
                newline_pos = content.rfind("\n", search_start, end)
                if newline_pos > start:
                    end = newline_pos + 1

            chunk = content[start:end]
            chunks.append(chunk)

            # Move start position with overlap
            if end >= len(content):
                break
            start = end - self.chunk_overlap

        logger.debug(f"Split {len(content)} chars into {len(chunks)} chunks")
        return chunks

    def process_chunks_in_parallel(
        self, chunks: list[str], processor_func, max_workers: int = 4
    ) -> list:
        """Process chunks in parallel.

        Args:
            chunks: List of content chunks
            processor_func: Function to process each chunk
            max_workers: Maximum number of parallel workers

        Returns:
            List of processing results
        """
        import concurrent.futures

        logger.debug(f"Processing {len(chunks)} chunks with {max_workers} workers")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(processor_func, chunk) for chunk in chunks]
            results = []

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Chunk processing failed: {e}")
                    results.append(None)

        return results


def is_file_too_large(file_path: Path, max_size_mb: int = 10) -> bool:
    """Check if file is too large for normal processing.

    Args:
        file_path: Path to file
        max_size_mb: Maximum size in MB

    Returns:
        True if file is too large
    """
    try:
        size_bytes = file_path.stat().st_size
        size_mb = size_bytes / (1024 * 1024)
        return size_mb > max_size_mb
    except Exception:
        return True  # If we can't stat it, assume it's too large


async def stream_file_to_stdin(
    file_path: Path, process: asyncio.subprocess.Process
) -> None:
    """Stream file content to a process stdin.

    Args:
        file_path: Path to file to stream
        process: Process to stream to
    """
    logger.debug(f"Streaming {file_path} to process stdin")

    reader = StreamingFileReader()

    try:
        async for chunk in reader.read_file_async(file_path):
            if process.stdin:
                process.stdin.write(chunk.encode("utf-8"))
                await process.stdin.drain()

        if process.stdin:
            process.stdin.close()
            await process.stdin.wait_closed()

    except Exception as e:
        logger.error(f"Error streaming file to stdin: {e}")
        if process.stdin:
            process.stdin.close()
        raise
