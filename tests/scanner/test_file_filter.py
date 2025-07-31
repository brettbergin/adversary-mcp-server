"""Tests for file filtering functionality."""

import tempfile
from pathlib import Path

import pytest

from adversary_mcp_server.scanner.file_filter import FileFilter


class TestFileFilter:
    """Test FileFilter functionality."""

    def test_init(self):
        """Test FileFilter initialization."""
        root_path = Path.cwd()
        file_filter = FileFilter(root_path)

        assert file_filter.root_path == root_path.resolve()
        assert file_filter.max_file_size_bytes == 10 * 1024 * 1024  # 10MB default
        assert file_filter.respect_gitignore is True

    def test_init_with_custom_params(self):
        """Test FileFilter initialization with custom parameters."""
        root_path = Path.cwd()
        custom_excludes = ["*.tmp", "build/*"]
        custom_includes = ["important.tmp"]

        file_filter = FileFilter(
            root_path=root_path,
            max_file_size_mb=5,
            respect_gitignore=False,
            custom_excludes=custom_excludes,
            custom_includes=custom_includes,
        )

        assert file_filter.max_file_size_bytes == 5 * 1024 * 1024  # 5MB
        assert file_filter.respect_gitignore is False
        assert file_filter.custom_excludes == custom_excludes
        assert file_filter.custom_includes == custom_includes

    def test_binary_file_detection_by_extension(self):
        """Test binary file detection by extension."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)
            file_filter = FileFilter(root_path)

            # Create test files
            binary_file = root_path / "test.exe"
            binary_file.touch()

            text_file = root_path / "test.py"
            text_file.write_text("print('hello')")

            assert file_filter._is_binary_file(binary_file) is True
            assert file_filter._is_binary_file(text_file) is False

    def test_binary_file_detection_by_content(self):
        """Test binary file detection by content."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)
            file_filter = FileFilter(root_path)

            # Create file with binary content (null bytes)
            binary_file = root_path / "test.unknown"
            binary_file.write_bytes(b"some text\x00binary data")

            # Create file with text content
            text_file = root_path / "test.unknown2"
            text_file.write_text("some text content")

            assert file_filter._is_binary_file(binary_file) is True
            assert file_filter._is_binary_file(text_file) is False

    def test_file_size_limit(self):
        """Test file size limit checking."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)
            file_filter = FileFilter(root_path, max_file_size_mb=1)  # 1MB limit

            # Create small file
            small_file = root_path / "small.txt"
            small_file.write_text("small content")

            # Create large file (simulate with metadata if possible)
            large_file = root_path / "large.txt"
            large_file.write_text("x" * (2 * 1024 * 1024))  # 2MB

            assert file_filter._is_too_large(small_file) is False
            assert file_filter._is_too_large(large_file) is True

    def test_default_excludes(self):
        """Test default exclude patterns."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)
            file_filter = FileFilter(root_path)

            # Create files that should be excluded
            (root_path / ".git").mkdir()
            git_file = root_path / ".git" / "config"
            git_file.touch()

            (root_path / "node_modules").mkdir()
            node_file = root_path / "node_modules" / "package.json"
            node_file.touch()

            # Create files that should be included
            source_file = root_path / "main.py"
            source_file.write_text("print('hello')")

            assert file_filter._matches_default_excludes(git_file) is True
            assert file_filter._matches_default_excludes(node_file) is True
            assert file_filter._matches_default_excludes(source_file) is False

    def test_gitignore_patterns(self):
        """Test .gitignore pattern matching."""
        pytest.importorskip("pathspec")  # Skip if pathspec not available

        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)

            # Create .gitignore file
            gitignore = root_path / ".gitignore"
            gitignore.write_text("*.log\nbuild/\n__pycache__/\n")

            file_filter = FileFilter(root_path, respect_gitignore=True)

            # Create test files
            log_file = root_path / "test.log"
            log_file.touch()

            (root_path / "build").mkdir()
            build_file = root_path / "build" / "output.txt"
            build_file.touch()

            source_file = root_path / "main.py"
            source_file.write_text("print('hello')")

            assert file_filter._matches_gitignore(log_file) is True
            assert file_filter._matches_gitignore(build_file) is True
            assert file_filter._matches_gitignore(source_file) is False

    def test_custom_excludes(self):
        """Test custom exclude patterns."""
        pytest.importorskip("pathspec")  # Skip if pathspec not available

        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)
            custom_excludes = ["*.tmp", "test_*"]

            file_filter = FileFilter(root_path, custom_excludes=custom_excludes)

            # Create test files
            tmp_file = root_path / "temp.tmp"
            tmp_file.touch()

            test_file = root_path / "test_file.py"
            test_file.touch()

            normal_file = root_path / "main.py"
            normal_file.write_text("print('hello')")

            assert (
                file_filter._matches_custom_patterns(tmp_file, custom_excludes) is True
            )
            assert (
                file_filter._matches_custom_patterns(test_file, custom_excludes) is True
            )
            assert (
                file_filter._matches_custom_patterns(normal_file, custom_excludes)
                is False
            )

    def test_custom_includes_override(self):
        """Test that custom includes override exclusions."""
        pytest.importorskip("pathspec")  # Skip if pathspec not available

        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)
            custom_excludes = ["*.tmp"]
            custom_includes = ["important.tmp"]

            file_filter = FileFilter(
                root_path,
                custom_excludes=custom_excludes,
                custom_includes=custom_includes,
            )

            # Create test files
            excluded_tmp = root_path / "temp.tmp"
            excluded_tmp.touch()

            included_tmp = root_path / "important.tmp"
            included_tmp.touch()

            # important.tmp should be included despite matching exclude pattern
            assert file_filter.should_include_file(excluded_tmp) is False
            assert file_filter.should_include_file(included_tmp) is True

    def test_should_include_file_integration(self):
        """Test the main should_include_file method."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)
            file_filter = FileFilter(root_path, max_file_size_mb=1)

            # Create various test files
            normal_file = root_path / "main.py"
            normal_file.write_text("print('hello')")

            binary_file = root_path / "app.exe"
            binary_file.touch()

            large_file = root_path / "large.txt"
            large_file.write_text("x" * (2 * 1024 * 1024))  # 2MB

            (root_path / ".git").mkdir()
            git_file = root_path / ".git" / "config"
            git_file.touch()

            # Test inclusions/exclusions
            assert file_filter.should_include_file(normal_file) is True
            assert file_filter.should_include_file(binary_file) is False  # Binary
            assert file_filter.should_include_file(large_file) is False  # Too large
            assert file_filter.should_include_file(git_file) is False  # Default exclude

    def test_filter_files_list(self):
        """Test filtering a list of files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)
            file_filter = FileFilter(root_path)

            # Create test files
            files = []

            good_file = root_path / "good.py"
            good_file.write_text("print('hello')")
            files.append(good_file)

            binary_file = root_path / "bad.exe"
            binary_file.touch()
            files.append(binary_file)

            (root_path / ".git").mkdir()
            git_file = root_path / ".git" / "config"
            git_file.touch()
            files.append(git_file)

            # Filter files
            filtered = file_filter.filter_files(files)

            assert len(filtered) == 1
            assert filtered[0] == good_file

    def test_get_stats(self):
        """Test getting filter statistics."""
        root_path = Path.cwd()
        custom_excludes = ["*.tmp"]
        custom_includes = ["important.tmp"]

        file_filter = FileFilter(
            root_path=root_path,
            max_file_size_mb=5,
            custom_excludes=custom_excludes,
            custom_includes=custom_includes,
        )

        stats = file_filter.get_stats()

        assert stats["root_path"] == str(root_path)
        assert stats["max_file_size_mb"] == 5
        assert stats["respect_gitignore"] is True
        assert stats["custom_excludes"] == 1
        assert stats["custom_includes"] == 1
        assert "pathspec_available" in stats


@pytest.mark.integration
class TestFileFilterIntegration:
    """Integration tests for FileFilter with real directory structures."""

    def test_filter_python_project_structure(self):
        """Test filtering a typical Python project structure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = Path(temp_dir)

            # Create typical Python project structure
            (root_path / "src").mkdir()
            (root_path / "src" / "main.py").write_text("print('main')")
            (root_path / "src" / "utils.py").write_text("def helper(): pass")

            (root_path / "tests").mkdir()
            (root_path / "tests" / "test_main.py").write_text("def test_main(): pass")

            (root_path / "__pycache__").mkdir()
            (root_path / "__pycache__" / "main.cpython-39.pyc").touch()

            (root_path / ".git").mkdir()
            (root_path / ".git" / "config").touch()

            (root_path / "build").mkdir()
            (root_path / "build" / "lib").mkdir()
            (root_path / "build" / "lib" / "main.so").touch()

            # Create .gitignore
            gitignore = root_path / ".gitignore"
            gitignore.write_text("__pycache__/\nbuild/\n*.pyc\n")

            # Find all files
            all_files = list(root_path.rglob("*"))
            all_files = [f for f in all_files if f.is_file()]

            # Filter files
            file_filter = FileFilter(root_path)
            filtered_files = file_filter.filter_files(all_files)

            # Should only include Python source files
            expected_files = {
                root_path / "src" / "main.py",
                root_path / "src" / "utils.py",
                root_path / "tests" / "test_main.py",
            }

            assert set(filtered_files) == expected_files
