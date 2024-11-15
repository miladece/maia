# tests/conftest.py
import pytest
import os
from maia_mail_assistant.config import ConfigManager
from maia_mail_assistant.models import AccountManager

@pytest.fixture
def config_manager():
    return ConfigManager()

@pytest.fixture
def account_manager():
    return AccountManager()


