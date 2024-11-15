import pytest
import os
from maia_mail_assistant.config import ConfigManager, SecureStorage

def test_config_manager_initialization():
    config_manager = ConfigManager()
    assert isinstance(config_manager.config, dict)
    assert 'openai_api_key' in config_manager.config
    assert 'assistants' in config_manager.config

def test_secure_storage():
    storage = SecureStorage()
    test_data = "test_secret"
    encrypted = storage.encrypt(test_data)
    decrypted = storage.decrypt(encrypted)
    assert decrypted == test_data
