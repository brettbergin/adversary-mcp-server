"""Comprehensive tests for ScanType value object to achieve 100% coverage."""

import pytest

from adversary_mcp_server.domain.value_objects.scan_type import ScanType


class TestScanType:
    """Test ScanType enumeration and its methods."""

    def test_scan_type_values(self):
        """Test that all scan type enum values are correct."""
        assert ScanType.FILE.value == "file"
        assert ScanType.DIRECTORY.value == "directory"
        assert ScanType.CODE.value == "code"
        assert ScanType.DIFF.value == "diff"

    def test_scan_type_str_representation(self):
        """Test string representation of scan types."""
        assert str(ScanType.FILE) == "file"
        assert str(ScanType.DIRECTORY) == "directory"
        assert str(ScanType.CODE) == "code"
        assert str(ScanType.DIFF) == "diff"

    def test_from_string_valid_cases(self):
        """Test creating ScanType from valid string values."""
        assert ScanType.from_string("file") == ScanType.FILE
        assert ScanType.from_string("directory") == ScanType.DIRECTORY
        assert ScanType.from_string("code") == ScanType.CODE
        assert ScanType.from_string("diff") == ScanType.DIFF

    def test_from_string_case_insensitive(self):
        """Test that from_string is case insensitive."""
        assert ScanType.from_string("FILE") == ScanType.FILE
        assert ScanType.from_string("Directory") == ScanType.DIRECTORY
        assert ScanType.from_string("CODE") == ScanType.CODE
        assert ScanType.from_string("DIFF") == ScanType.DIFF

    def test_from_string_mixed_case(self):
        """Test from_string with mixed case."""
        assert ScanType.from_string("FiLe") == ScanType.FILE
        assert ScanType.from_string("DiReCtOrY") == ScanType.DIRECTORY
        assert ScanType.from_string("CoDe") == ScanType.CODE
        assert ScanType.from_string("DiFf") == ScanType.DIFF

    def test_from_string_invalid_value(self):
        """Test that invalid string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid scan type: invalid"):
            ScanType.from_string("invalid")

        with pytest.raises(ValueError, match="Invalid scan type: unknown"):
            ScanType.from_string("unknown")

        with pytest.raises(ValueError, match="Invalid scan type: "):
            ScanType.from_string("")

    def test_from_string_whitespace_and_special_chars(self):
        """Test from_string with whitespace and special characters."""
        with pytest.raises(ValueError, match="Invalid scan type:  file "):
            ScanType.from_string(" file ")

        with pytest.raises(ValueError, match="Invalid scan type: file-name"):
            ScanType.from_string("file-name")

        with pytest.raises(ValueError, match="Invalid scan type: file_type"):
            ScanType.from_string("file_type")

    def test_is_file_based_true_cases(self):
        """Test is_file_based method for file-based scan types."""
        assert ScanType.FILE.is_file_based() is True
        assert ScanType.DIRECTORY.is_file_based() is True
        assert ScanType.DIFF.is_file_based() is True

    def test_is_file_based_false_cases(self):
        """Test is_file_based method for non-file-based scan types."""
        assert ScanType.CODE.is_file_based() is False

    def test_is_content_based_true_cases(self):
        """Test is_content_based method for content-based scan types."""
        assert ScanType.CODE.is_content_based() is True

    def test_is_content_based_false_cases(self):
        """Test is_content_based method for non-content-based scan types."""
        assert ScanType.FILE.is_content_based() is False
        assert ScanType.DIRECTORY.is_content_based() is False
        assert ScanType.DIFF.is_content_based() is False

    def test_requires_file_system_true_cases(self):
        """Test requires_file_system method for file system requiring types."""
        assert ScanType.FILE.requires_file_system() is True
        assert ScanType.DIRECTORY.requires_file_system() is True
        assert ScanType.DIFF.requires_file_system() is True

    def test_requires_file_system_false_cases(self):
        """Test requires_file_system method for non-file system requiring types."""
        assert ScanType.CODE.requires_file_system() is False

    def test_all_scan_types_covered(self):
        """Test that all scan type values are covered in our tests."""
        all_scan_types = list(ScanType)
        expected_types = [
            ScanType.FILE,
            ScanType.DIRECTORY,
            ScanType.CODE,
            ScanType.DIFF,
        ]

        assert len(all_scan_types) == len(expected_types)
        for scan_type in expected_types:
            assert scan_type in all_scan_types

    def test_scan_type_iteration(self):
        """Test that ScanType can be iterated over."""
        scan_types = list(ScanType)
        assert len(scan_types) == 4
        assert ScanType.FILE in scan_types
        assert ScanType.DIRECTORY in scan_types
        assert ScanType.CODE in scan_types
        assert ScanType.DIFF in scan_types

    def test_scan_type_equality(self):
        """Test scan type equality comparisons."""
        assert ScanType.FILE == ScanType.FILE
        assert ScanType.DIRECTORY == ScanType.DIRECTORY
        assert ScanType.CODE == ScanType.CODE
        assert ScanType.DIFF == ScanType.DIFF

        assert ScanType.FILE != ScanType.DIRECTORY
        assert ScanType.CODE != ScanType.DIFF

    def test_scan_type_membership(self):
        """Test membership operations with scan types."""
        file_based_types = (ScanType.FILE, ScanType.DIRECTORY, ScanType.DIFF)

        assert ScanType.FILE in file_based_types
        assert ScanType.DIRECTORY in file_based_types
        assert ScanType.DIFF in file_based_types
        assert ScanType.CODE not in file_based_types

    def test_comprehensive_boolean_matrix(self):
        """Test all boolean methods for all scan types comprehensively."""
        # Create a matrix of expected results
        test_matrix = {
            ScanType.FILE: {
                "is_file_based": True,
                "is_content_based": False,
                "requires_file_system": True,
            },
            ScanType.DIRECTORY: {
                "is_file_based": True,
                "is_content_based": False,
                "requires_file_system": True,
            },
            ScanType.CODE: {
                "is_file_based": False,
                "is_content_based": True,
                "requires_file_system": False,
            },
            ScanType.DIFF: {
                "is_file_based": True,
                "is_content_based": False,
                "requires_file_system": True,
            },
        }

        for scan_type, expected in test_matrix.items():
            assert (
                scan_type.is_file_based() == expected["is_file_based"]
            ), f"is_file_based failed for {scan_type}"
            assert (
                scan_type.is_content_based() == expected["is_content_based"]
            ), f"is_content_based failed for {scan_type}"
            assert (
                scan_type.requires_file_system() == expected["requires_file_system"]
            ), f"requires_file_system failed for {scan_type}"

    def test_scan_type_hash(self):
        """Test that scan types are hashable and can be used as dict keys."""
        scan_type_dict = {
            ScanType.FILE: "file_handler",
            ScanType.DIRECTORY: "directory_handler",
            ScanType.CODE: "code_handler",
            ScanType.DIFF: "diff_handler",
        }

        assert scan_type_dict[ScanType.FILE] == "file_handler"
        assert scan_type_dict[ScanType.DIRECTORY] == "directory_handler"
        assert scan_type_dict[ScanType.CODE] == "code_handler"
        assert scan_type_dict[ScanType.DIFF] == "diff_handler"

    def test_scan_type_repr(self):
        """Test string representation contains enum name."""
        assert "ScanType.FILE" in repr(ScanType.FILE)
        assert "ScanType.DIRECTORY" in repr(ScanType.DIRECTORY)
        assert "ScanType.CODE" in repr(ScanType.CODE)
        assert "ScanType.DIFF" in repr(ScanType.DIFF)


class TestScanTypeEdgeCases:
    """Test edge cases and error conditions for ScanType."""

    def test_from_string_none_value(self):
        """Test from_string with None value."""
        with pytest.raises(AttributeError):
            ScanType.from_string(None)

    def test_from_string_numeric_values(self):
        """Test from_string with numeric values."""
        with pytest.raises(ValueError):
            ScanType.from_string("1")

        with pytest.raises(ValueError):
            ScanType.from_string("0")

    def test_from_string_boolean_strings(self):
        """Test from_string with boolean string values."""
        with pytest.raises(ValueError):
            ScanType.from_string("true")

        with pytest.raises(ValueError):
            ScanType.from_string("false")

    def test_scan_type_logical_consistency(self):
        """Test logical consistency between methods."""
        for scan_type in ScanType:
            # A scan type cannot be both file-based and content-based
            if scan_type.is_file_based():
                assert (
                    not scan_type.is_content_based()
                ), f"{scan_type} cannot be both file and content based"

            if scan_type.is_content_based():
                assert (
                    not scan_type.is_file_based()
                ), f"{scan_type} cannot be both content and file based"

            # Content-based types should not require file system
            if scan_type.is_content_based():
                assert (
                    not scan_type.requires_file_system()
                ), f"Content-based {scan_type} should not require file system"

    def test_scan_type_completeness(self):
        """Test that every scan type falls into exactly one category."""
        for scan_type in ScanType:
            categories = [scan_type.is_file_based(), scan_type.is_content_based()]

            # Each scan type should belong to exactly one category
            assert (
                sum(categories) == 1
            ), f"{scan_type} should belong to exactly one category"


class TestScanTypeIntegration:
    """Integration tests showing how ScanType would be used in practice."""

    def test_scan_type_routing_logic(self):
        """Test how scan types might be used for routing in application logic."""

        def get_handler_type(scan_type: ScanType) -> str:
            if scan_type.is_file_based():
                return "filesystem_handler"
            elif scan_type.is_content_based():
                return "content_handler"
            else:
                return "unknown_handler"

        assert get_handler_type(ScanType.FILE) == "filesystem_handler"
        assert get_handler_type(ScanType.DIRECTORY) == "filesystem_handler"
        assert get_handler_type(ScanType.DIFF) == "filesystem_handler"
        assert get_handler_type(ScanType.CODE) == "content_handler"

    def test_scan_type_validation_logic(self):
        """Test how scan types might be used for validation."""

        def requires_path_validation(scan_type: ScanType) -> bool:
            return scan_type.requires_file_system()

        assert requires_path_validation(ScanType.FILE) is True
        assert requires_path_validation(ScanType.DIRECTORY) is True
        assert requires_path_validation(ScanType.DIFF) is True
        assert requires_path_validation(ScanType.CODE) is False

    def test_scan_type_permission_logic(self):
        """Test how scan types might affect permission requirements."""

        def needs_file_permissions(scan_type: ScanType) -> bool:
            return scan_type.requires_file_system()

        def needs_content_validation(scan_type: ScanType) -> bool:
            return scan_type.is_content_based()

        # File-based scans need file permissions
        for scan_type in [ScanType.FILE, ScanType.DIRECTORY, ScanType.DIFF]:
            assert needs_file_permissions(scan_type) is True
            assert needs_content_validation(scan_type) is False

        # Content-based scans need content validation
        assert needs_file_permissions(ScanType.CODE) is False
        assert needs_content_validation(ScanType.CODE) is True

    def test_scan_type_serialization_roundtrip(self):
        """Test that scan types can be serialized and deserialized."""
        for scan_type in ScanType:
            # Serialize to string
            serialized = str(scan_type)

            # Deserialize back
            deserialized = ScanType.from_string(serialized)

            # Should be equal
            assert deserialized == scan_type
