"""Tests for LanguageMapper module."""

from pathlib import Path

from adversary_mcp_server.scanner.language_mapping import LanguageMapper


class TestLanguageMapper:
    """Test cases for LanguageMapper."""

    def test_detect_language_from_extension_common_languages(self):
        """Test language detection for common file extensions."""
        test_cases = [
            ("test.py", "python"),
            ("script.js", "javascript"),
            ("component.tsx", "typescript"),
            ("Main.java", "java"),
            ("server.go", "go"),
            ("index.php", "php"),
            ("script.rb", "ruby"),
            ("main.c", "c"),
            ("app.cpp", "cpp"),
            ("Program.cs", "csharp"),
            ("lib.rs", "rust"),
        ]

        for file_path, expected_lang in test_cases:
            result = LanguageMapper.detect_language_from_extension(file_path)
            assert result == expected_lang

    def test_detect_language_from_extension_path_object(self):
        """Test language detection with Path objects."""
        test_path = Path("test.py")
        result = LanguageMapper.detect_language_from_extension(test_path)
        assert result == "python"

    def test_detect_language_from_extension_case_insensitive(self):
        """Test that extension detection is case insensitive."""
        test_cases = [
            ("test.PY", "python"),
            ("script.JS", "javascript"),
            ("data.JSON", "json"),
            ("config.YAML", "yaml"),
        ]

        for file_path, expected_lang in test_cases:
            result = LanguageMapper.detect_language_from_extension(file_path)
            assert result == expected_lang

    def test_detect_language_from_extension_unknown(self):
        """Test language detection for unknown extensions."""
        test_cases = [
            "test.unknown",
            "file.xyz",
            "document.abc123",
            "noextension",
            "",
        ]

        for file_path in test_cases:
            result = LanguageMapper.detect_language_from_extension(file_path)
            assert result == "generic"

    def test_detect_language_from_extension_web_technologies(self):
        """Test detection for web technology extensions."""
        test_cases = [
            ("index.html", "html"),
            ("styles.css", "css"),
            ("styles.scss", "scss"),
            ("component.vue", "vue"),
            ("app.svelte", "svelte"),
        ]

        for file_path, expected_lang in test_cases:
            result = LanguageMapper.detect_language_from_extension(file_path)
            assert result == expected_lang

    def test_detect_language_from_extension_shell_scripts(self):
        """Test detection for shell script extensions."""
        test_cases = [
            ("script.sh", "bash"),
            ("install.bash", "bash"),
            ("config.zsh", "bash"),
            ("deploy.ps1", "powershell"),
            ("setup.bat", "batch"),
        ]

        for file_path, expected_lang in test_cases:
            result = LanguageMapper.detect_language_from_extension(file_path)
            assert result == expected_lang

    def test_detect_language_from_extension_data_formats(self):
        """Test detection for data format extensions."""
        test_cases = [
            ("config.json", "json"),
            ("data.yaml", "yaml"),
            ("settings.yml", "yaml"),
            ("project.toml", "toml"),
            ("data.xml", "xml"),
            ("report.csv", "csv"),
        ]

        for file_path, expected_lang in test_cases:
            result = LanguageMapper.detect_language_from_extension(file_path)
            assert result == expected_lang

    def test_get_extension_for_language_common(self):
        """Test getting extensions for common languages."""
        test_cases = [
            ("python", ".py"),
            ("javascript", ".js"),
            ("typescript", ".ts"),
            ("java", ".java"),
            ("go", ".go"),
            ("rust", ".rs"),
            ("c", ".c"),
            ("cpp", ".cpp"),
            ("csharp", ".cs"),
        ]

        for language, expected_ext in test_cases:
            result = LanguageMapper.get_extension_for_language(language)
            assert result == expected_ext

    def test_get_extension_for_language_case_insensitive(self):
        """Test that language lookup is case insensitive."""
        test_cases = [
            ("PYTHON", ".py"),
            ("JavaScript", ".js"),
            ("TypeScript", ".ts"),
            ("C++", ".cpp"),
            ("C#", ".cs"),
        ]

        for language, expected_ext in test_cases:
            result = LanguageMapper.get_extension_for_language(language)
            assert result == expected_ext

    def test_get_extension_for_language_unknown(self):
        """Test getting extension for unknown language."""
        test_cases = [
            "unknown_language",
            "nonexistent",
            "",
            None,
        ]

        for language in test_cases:
            result = LanguageMapper.get_extension_for_language(language)
            assert result == ".txt"

    def test_get_extension_for_language_object_with_value(self):
        """Test getting extension for object with value attribute."""

        class MockLanguageEnum:
            def __init__(self, value):
                self.value = value

        mock_lang = MockLanguageEnum("python")
        result = LanguageMapper.get_extension_for_language(mock_lang)
        assert result == ".py"

    def test_get_extension_for_language_non_string_object(self):
        """Test getting extension for non-string object."""

        class MockObject:
            def __init__(self, value):
                self._value = value

            def __str__(self):
                return self._value

        mock_obj = MockObject("python")
        result = LanguageMapper.get_extension_for_language(mock_obj)
        assert result == ".py"

    def test_is_supported_language_valid(self):
        """Test checking if valid languages are supported."""
        supported_languages = [
            "python",
            "javascript",
            "typescript",
            "java",
            "go",
            "rust",
            "c",
            "cpp",
            "html",
            "css",
        ]

        for language in supported_languages:
            assert LanguageMapper.is_supported_language(language) is True

    def test_is_supported_language_case_insensitive(self):
        """Test that language support check is case insensitive."""
        test_cases = [
            "PYTHON",
            "JavaScript",
            "TypeScript",
            "HTML",
            "CSS",
        ]

        for language in test_cases:
            assert LanguageMapper.is_supported_language(language) is True

    def test_is_supported_language_invalid(self):
        """Test checking if invalid languages are supported."""
        unsupported_languages = [
            "unknown_language",
            "nonexistent",
            "",
            None,
        ]

        for language in unsupported_languages:
            assert LanguageMapper.is_supported_language(language) is False

    def test_is_supported_extension_valid(self):
        """Test checking if valid extensions are supported."""
        supported_extensions = [
            ".py",
            ".js",
            ".ts",
            ".java",
            ".go",
            ".rs",
            ".html",
            ".css",
        ]

        for extension in supported_extensions:
            assert LanguageMapper.is_supported_extension(extension) is True

    def test_is_supported_extension_without_dot(self):
        """Test extension support check without leading dot."""
        test_cases = [
            "py",
            "js",
            "ts",
            "java",
            "html",
            "css",
        ]

        for extension in test_cases:
            assert LanguageMapper.is_supported_extension(extension) is True

    def test_is_supported_extension_case_insensitive(self):
        """Test that extension support check is case insensitive."""
        test_cases = [
            ".PY",
            ".JS",
            ".HTML",
            ".CSS",
            "PY",  # Without dot and uppercase
            "JS",
        ]

        for extension in test_cases:
            assert LanguageMapper.is_supported_extension(extension) is True

    def test_is_supported_extension_invalid(self):
        """Test checking if invalid extensions are supported."""
        unsupported_extensions = [
            ".unknown",
            ".xyz",
            "",
            None,
            "unknown",  # Without dot
        ]

        for extension in unsupported_extensions:
            assert LanguageMapper.is_supported_extension(extension) is False

    def test_get_supported_languages(self):
        """Test getting list of supported languages."""
        languages = LanguageMapper.get_supported_languages()

        assert isinstance(languages, list)
        assert len(languages) > 0

        # Check that list is sorted
        assert languages == sorted(languages)

        # Verify some expected languages are present
        expected_languages = ["python", "javascript", "java", "go", "rust"]
        for lang in expected_languages:
            assert lang in languages

    def test_get_supported_extensions(self):
        """Test getting list of supported extensions."""
        extensions = LanguageMapper.get_supported_extensions()

        assert isinstance(extensions, list)
        assert len(extensions) > 0

        # Check that list is sorted
        assert extensions == sorted(extensions)

        # Verify some expected extensions are present
        expected_extensions = [".py", ".js", ".java", ".go", ".rs"]
        for ext in expected_extensions:
            assert ext in extensions

        # All extensions should start with dot
        for ext in extensions:
            assert ext.startswith(".")

    def test_language_extension_mappings_consistency(self):
        """Test that language and extension mappings are consistent."""
        # Test that every language has a corresponding extension
        for language in LanguageMapper.LANGUAGE_TO_EXTENSION:
            extension = LanguageMapper.LANGUAGE_TO_EXTENSION[language]
            assert extension.startswith(".")

        # Test that extensions map to languages correctly
        for extension in LanguageMapper.EXTENSION_TO_LANGUAGE:
            language = LanguageMapper.EXTENSION_TO_LANGUAGE[extension]
            assert isinstance(language, str)
            assert len(language) > 0

    def test_comprehensive_php_extensions(self):
        """Test comprehensive PHP extension support."""
        php_extensions = [".php", ".php3", ".php4", ".php5", ".phtml"]

        for ext in php_extensions:
            result = LanguageMapper.detect_language_from_extension(f"test{ext}")
            assert result == "php"

    def test_comprehensive_cpp_extensions(self):
        """Test comprehensive C++ extension support."""
        cpp_extensions = [".cpp", ".cc", ".cxx", ".hpp", ".hxx"]

        for ext in cpp_extensions:
            result = LanguageMapper.detect_language_from_extension(f"test{ext}")
            assert result == "cpp"

    def test_javascript_variant_extensions(self):
        """Test JavaScript variant extension support."""
        js_extensions = [".js", ".mjs", ".cjs", ".jsx"]

        for ext in js_extensions:
            result = LanguageMapper.detect_language_from_extension(f"test{ext}")
            assert result == "javascript"
