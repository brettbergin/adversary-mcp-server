import logging
from unittest.mock import Mock, patch

import pytest


@pytest.fixture(autouse=True, scope="session")
def mock_keyring_session():
    """Mock keyring for entire test session to prevent any keychain access."""
    # Mock keyring at the module level
    mock_storage = {}

    def mock_get_password(service, username):
        key = f"{service}:{username}"
        return mock_storage.get(key)

    def mock_set_password(service, username, password):
        key = f"{service}:{username}"
        mock_storage[key] = password

    def mock_delete_password(service, username):
        key = f"{service}:{username}"
        mock_storage.pop(key, None)

    # Patch keyring module functions
    with (
        patch("keyring.get_password", mock_get_password),
        patch("keyring.set_password", mock_set_password),
        patch("keyring.delete_password", mock_delete_password),
    ):
        yield


@pytest.fixture(autouse=True)
def reset_credential_singleton():
    """Reset credential manager singleton before each test for isolation."""
    # Import here to ensure keyring is already mocked
    from adversary_mcp_server.credentials import reset_credential_manager

    reset_credential_manager()
    yield
    # Reset again after test to clean up
    reset_credential_manager()


@pytest.fixture(autouse=True)
def reset_config_manager_singleton():
    """Reset config manager singleton before each test for isolation."""
    # Import here to avoid circular imports
    from adversary_mcp_server.config_manager import reset_config_manager

    reset_config_manager()
    yield
    # Reset again after test to clean up
    reset_config_manager()


@pytest.fixture(autouse=True, scope="session")
def setup_test_logging():
    """Configure separate test logging to avoid polluting main log file."""
    # Import here to avoid circular imports
    from adversary_mcp_server.logger import setup_test_logging

    setup_test_logging()
    yield


@pytest.fixture(autouse=True)
def mute_logs():
    logging.getLogger().setLevel(logging.WARNING)


@pytest.fixture(autouse=True)
def prevent_network_calls():
    """Global fixture to prevent accidental network calls in tests."""
    # Mock subprocess calls that could make network requests
    mock_subprocess = Mock()

    def smart_subprocess_run(args, **kwargs):
        """Smart subprocess.run mock that allows semgrep version checks."""
        # Allow semgrep version checks
        if isinstance(args, list) and len(args) >= 2 and args[1] == "--version":
            # Mock a successful semgrep version check
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = b"semgrep 1.0.0"
            mock_result.stderr = b""
            return mock_result

        # Block other subprocess calls
        raise RuntimeError(
            "Real subprocess.run() calls are not allowed in tests! "
            "Please mock this call to prevent accidental network requests."
        )

    mock_subprocess.run = smart_subprocess_run
    mock_subprocess.call = Mock(
        side_effect=RuntimeError(
            "Real subprocess.call() calls are not allowed in tests! "
            "Please mock this call to prevent accidental network requests."
        )
    )
    mock_subprocess.check_call = Mock(
        side_effect=RuntimeError(
            "Real subprocess.check_call() calls are not allowed in tests! "
            "Please mock this call to prevent accidental network requests."
        )
    )
    mock_subprocess.check_output = Mock(
        side_effect=RuntimeError(
            "Real subprocess.check_output() calls are not allowed in tests! "
            "Please mock this call to prevent accidental network requests."
        )
    )

    # Create a special mock for Popen that supports type subscripting
    class MockPopenMeta(type):
        def __getitem__(cls, item):
            # Support type subscripting like Popen[bytes]
            return cls

    class MockPopen(metaclass=MockPopenMeta):
        def __init__(self, *args, **kwargs):
            raise RuntimeError(
                "Real subprocess.Popen() calls are not allowed in tests! "
                "Please mock this call to prevent accidental network requests."
            )

        def __getitem__(self, item):
            # Support type subscripting like Popen[bytes]
            return self

    mock_subprocess.Popen = MockPopen

    with (
        patch("subprocess.run", mock_subprocess.run),
        patch("subprocess.call", mock_subprocess.call),
        patch("subprocess.check_call", mock_subprocess.check_call),
        patch("subprocess.check_output", mock_subprocess.check_output),
        patch("subprocess.Popen", mock_subprocess.Popen),
    ):
        yield
