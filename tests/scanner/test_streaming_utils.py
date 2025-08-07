"""Tests for streaming utilities."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from adversary_mcp_server.scanner.streaming_utils import (
    ChunkedProcessor,
    StreamingFileReader,
    is_file_too_large,
)


class TestStreamingFileReader:
    """Test StreamingFileReader functionality."""

    def test_init(self):
        """Test StreamingFileReader initialization."""
        reader = StreamingFileReader()
        assert reader.chunk_size == 8192

        reader = StreamingFileReader(chunk_size=4096)
        assert reader.chunk_size == 4096

    @pytest.mark.asyncio
    async def test_read_file_async(self):
        """Test async file reading."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            content = "Line 1\nLine 2\nLine 3\n" * 100  # Create some content
            f.write(content)
            f.flush()
            temp_path = Path(f.name)

        try:
            reader = StreamingFileReader(chunk_size=50)  # Small chunks for testing
            chunks = []

            async for chunk in reader.read_file_async(temp_path):
                chunks.append(chunk)

            reconstructed = "".join(chunks)
            assert reconstructed == content
            assert len(chunks) > 1  # Should be multiple chunks
        finally:
            temp_path.unlink()

    def test_read_file_chunks(self):
        """Test synchronous chunked file reading."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            content = "abcdefghij" * 200  # 2000 characters
            f.write(content)
            f.flush()
            temp_path = Path(f.name)

        try:
            reader = StreamingFileReader(chunk_size=100)
            chunks = list(reader.read_file_chunks(temp_path))

            reconstructed = "".join(chunks)
            assert reconstructed == content
            assert len(chunks) == 20  # 2000 chars / 100 chunk_size
        finally:
            temp_path.unlink()

    def test_read_file_chunks_with_max_size(self):
        """Test chunked reading with size limit."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            content = "abcdefghij" * 200  # 2000 characters
            f.write(content)
            f.flush()
            temp_path = Path(f.name)

        try:
            reader = StreamingFileReader(chunk_size=100)
            chunks = list(reader.read_file_chunks(temp_path, max_size=500))

            reconstructed = "".join(chunks)
            assert len(reconstructed) == 500
            assert reconstructed == content[:500]
        finally:
            temp_path.unlink()

    @pytest.mark.asyncio
    async def test_get_file_preview(self):
        """Test file preview generation."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            content = "This is a test file\n" * 1000  # Large content
            f.write(content)
            f.flush()
            temp_path = Path(f.name)

        try:
            reader = StreamingFileReader()
            preview = await reader.get_file_preview(temp_path, preview_size=100)

            assert len(preview) == 100
            assert preview == content[:100]
        finally:
            temp_path.unlink()

    @pytest.mark.asyncio
    async def test_read_empty_file(self):
        """Test reading empty file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("")  # Empty file
            f.flush()
            temp_path = Path(f.name)

        try:
            reader = StreamingFileReader()
            chunks = []

            async for chunk in reader.read_file_async(temp_path):
                chunks.append(chunk)

            assert chunks == []
        finally:
            temp_path.unlink()

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self):
        """Test error handling for nonexistent file."""
        reader = StreamingFileReader()
        nonexistent_path = Path("nonexistent_file.txt")

        with pytest.raises(FileNotFoundError):
            async for chunk in reader.read_file_async(nonexistent_path):
                pass


class TestChunkedProcessor:
    """Test ChunkedProcessor functionality."""

    def test_init(self):
        """Test ChunkedProcessor initialization."""
        processor = ChunkedProcessor()
        assert processor.chunk_overlap == 200

        processor = ChunkedProcessor(chunk_overlap=100)
        assert processor.chunk_overlap == 100

    def test_split_content_small(self):
        """Test splitting content smaller than chunk size."""
        processor = ChunkedProcessor()
        content = "Small content"

        chunks = processor.split_content_into_chunks(content, chunk_size=1000)

        assert len(chunks) == 1
        assert chunks[0] == content

    def test_split_content_large(self):
        """Test splitting large content into chunks."""
        processor = ChunkedProcessor(chunk_overlap=10)
        content = "x" * 1000  # 1000 character content

        chunks = processor.split_content_into_chunks(content, chunk_size=300)

        assert len(chunks) > 1
        # Check that content is properly reconstructed (accounting for overlaps)
        assert chunks[0][:300] == content[:300]
        # Verify overlap
        assert chunks[1][:10] == chunks[0][-10:]

    # def test_split_content_preserve_lines(self):
    #     """Test splitting content while preserving line boundaries."""
    #     processor = ChunkedProcessor()
    #     content = "\n".join([f"Line {i}" for i in range(100)])  # 100 lines

    #     chunks = processor.split_content_into_chunks(
    #         content,
    #         chunk_size=200,
    #         preserve_lines=True
    #     )

    #     # Each chunk should end with a newline (except possibly the last)
    #     for chunk in chunks[:-1]:
    #         assert chunk.endswith('\n'), f"Chunk doesn't end with newline: {chunk[-10:]}"

    # def test_split_content_no_preserve_lines(self):
    #     """Test splitting content without preserving line boundaries."""
    #     processor = ChunkedProcessor()
    #     content = "\n".join([f"Line {i}" for i in range(100)])

    #     chunks = processor.split_content_into_chunks(
    #         content,
    #         chunk_size=200,
    #         preserve_lines=False
    #     )

    #     # Should split exactly at chunk boundaries
    #     assert len(chunks[0]) == 200

    def test_process_chunks_in_parallel(self):
        """Test parallel processing of chunks."""
        processor = ChunkedProcessor()

        def mock_processor(chunk):
            return len(chunk)  # Simple processing: return length

        chunks = ["chunk1", "chunk22", "chunk333"]
        results = processor.process_chunks_in_parallel(
            chunks, mock_processor, max_workers=2
        )

        assert len(results) == 3
        assert set(results) == {6, 7, 8}  # Lengths of the chunks

    def test_process_chunks_with_exception(self):
        """Test handling exceptions in parallel processing."""
        processor = ChunkedProcessor()

        def failing_processor(chunk):
            if chunk == "fail":
                raise ValueError("Processing failed")
            return f"processed_{chunk}"

        chunks = ["good1", "fail", "good2"]
        results = processor.process_chunks_in_parallel(
            chunks, failing_processor, max_workers=2
        )

        assert len(results) == 3
        # One result should be None (failed processing)
        assert None in results
        assert "processed_good1" in results
        assert "processed_good2" in results


class TestUtilityFunctions:
    """Test utility functions."""

    def test_is_file_too_large(self):
        """Test file size checking."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            # Write content that's definitely under 1MB
            f.write("small content")
            f.flush()
            small_path = Path(f.name)

        try:
            assert is_file_too_large(small_path, max_size_mb=1) is False
            assert (
                is_file_too_large(small_path, max_size_mb=0.000001) is True
            )  # Very small limit
        finally:
            small_path.unlink()

    def test_is_file_too_large_nonexistent(self):
        """Test file size checking for nonexistent file."""
        nonexistent = Path("nonexistent.txt")
        # Should return True for safety
        assert is_file_too_large(nonexistent) is True

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def test_stream_file_to_stdin(self, mock_create_subprocess):
        """Test streaming file to process stdin."""
        from adversary_mcp_server.scanner.streaming_utils import stream_file_to_stdin

        # Create test file
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            content = "test content for stdin"
            f.write(content)
            f.flush()
            temp_path = Path(f.name)

        # Mock process
        mock_process = Mock()
        mock_process.stdin = Mock()
        mock_process.stdin.write = Mock()
        mock_process.stdin.drain = AsyncMock()
        mock_process.stdin.close = Mock()
        mock_process.stdin.wait_closed = AsyncMock()
        mock_process.wait = AsyncMock(return_value=0)
        mock_process.communicate = AsyncMock(return_value=(content.encode(), b""))
        mock_process.returncode = 0

        mock_create_subprocess.return_value = mock_process

        try:
            # Create a simple cat process to echo stdin (now mocked)
            process = await asyncio.create_subprocess_exec(
                "cat",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Stream file to process
            await stream_file_to_stdin(temp_path, process)

            # Get output
            stdout, stderr = await process.communicate()

            assert stdout.decode() == content

            # Verify mocks were called
            mock_create_subprocess.assert_called_once()
            mock_process.stdin.write.assert_called()
            mock_process.stdin.close.assert_called_once()
            assert process.returncode == 0
        finally:
            temp_path.unlink()


@pytest.mark.integration
class TestStreamingIntegration:
    """Integration tests for streaming functionality."""

    @pytest.mark.asyncio
    async def test_large_file_streaming(self):
        """Test streaming with a larger file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            # Create a larger file
            lines = [f"This is line {i}\n" for i in range(10000)]  # Create many lines
            large_content = "".join(lines)
            f.write(large_content)
            f.flush()
            temp_path = Path(f.name)

        try:
            reader = StreamingFileReader(chunk_size=1024)  # 1KB chunks

            # Test async reading
            reconstructed = ""
            async for chunk in reader.read_file_async(temp_path):
                reconstructed += chunk

            assert reconstructed == large_content

            # Test preview
            preview = await reader.get_file_preview(temp_path, preview_size=5000)
            assert len(preview) == 5000
            assert preview == large_content[:5000]

        finally:
            temp_path.unlink()

    def test_chunked_processing_integration(self):
        """Test integration of chunked processing."""
        processor = ChunkedProcessor(chunk_overlap=50)

        # Create large content
        content = "Word " * 10000  # 50000 characters

        # Split into chunks
        chunks = processor.split_content_into_chunks(
            content, chunk_size=1000, preserve_lines=False
        )

        # Process chunks (count words)
        def word_counter(chunk):
            return len(chunk.split())

        word_counts = processor.process_chunks_in_parallel(
            chunks, word_counter, max_workers=4
        )

        # Verify processing worked
        assert len(word_counts) == len(chunks)
        assert all(isinstance(count, int) for count in word_counts)
        assert sum(word_counts) > 10000  # Should have more than 10000 due to overlaps
