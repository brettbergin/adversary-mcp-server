import logging

import pytest


@pytest.fixture(autouse=True)
def mute_logs():
    logging.getLogger().setLevel(logging.WARNING)
