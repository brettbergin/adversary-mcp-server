import logging
from unittest.mock import Mock, patch

import pytest


@pytest.fixture(autouse=True)
def mute_logs():
    logging.getLogger().setLevel(logging.WARNING)


@pytest.fixture(autouse=True)
def prevent_network_calls():
    """Global fixture to prevent accidental network calls in tests."""
    # Mock subprocess calls that could make network requests
    mock_subprocess = Mock()
    mock_subprocess.run = Mock(
        side_effect=RuntimeError(
            "Real subprocess.run() calls are not allowed in tests! "
            "Please mock this call to prevent accidental network requests."
        )
    )
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
    mock_subprocess.Popen = Mock(
        side_effect=RuntimeError(
            "Real subprocess.Popen() calls are not allowed in tests! "
            "Please mock this call to prevent accidental network requests."
        )
    )

    with (
        patch("subprocess.run", mock_subprocess.run),
        patch("subprocess.call", mock_subprocess.call),
        patch("subprocess.check_call", mock_subprocess.check_call),
        patch("subprocess.check_output", mock_subprocess.check_output),
        patch("subprocess.Popen", mock_subprocess.Popen),
    ):
        yield
