import pytest
from maia_mail_assistant.email_providers import GmailProvider, ExchangeProvider, SMTPProvider

def test_gmail_provider_initialization():
    provider = GmailProvider()
    assert provider.service is None
    assert provider.credentials_path is None
    assert isinstance(provider.SCOPES, list)

def test_exchange_provider_initialization():
    provider = ExchangeProvider()
    assert provider.access_token is None
    assert isinstance(provider.SCOPES, list)

def test_smtp_provider_initialization():
    test_email = "test@example.com"
    test_password = "password"
    test_smtp_server = "smtp.example.com"
    test_smtp_port = 587
    
    provider = SMTPProvider(
        email=test_email,
        password=test_password,
        smtp_server=test_smtp_server,
        smtp_port=test_smtp_port
    )
    
    assert provider.email == test_email
    assert provider.smtp_server == test_smtp_server
    assert provider.smtp_port == test_smtp_port
