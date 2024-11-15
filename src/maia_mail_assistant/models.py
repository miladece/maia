import os
import json
import re
from typing import Dict, Optional
from tkinter import messagebox
from typing import Dict, Optional

from .config import SecureStorage
from .email_providers import EmailProvider, SMTPProvider, GmailProvider, ExchangeProvider

class EmailAccount:
    """Represents an email account with its configuration and provider."""
    
    def __init__(self, account_type: str, email: str, provider: EmailProvider, signature: str = ""):
        self.account_type = account_type
        self.email = email
        self.provider = provider
        self.signature = signature
        
    def to_dict(self) -> Dict:
        """Convert account to dictionary for serialization."""
        return {
            'account_type': self.account_type,
            'email': self.email,
            'signature': self.signature
        }

class AccountManager:
    """Manages email accounts including persistence and validation."""
    
    def __init__(self):
        print("Initializing AccountManager")
        self.accounts = {}
        self.config_file = 'email_accounts_config.json'
        self.secure_storage = SecureStorage()
        try:
            self.load_accounts()
        except Exception as e:
            print(f"Error loading accounts: {e}")
            self.accounts = {}
        print(f"AccountManager initialized with {len(self.accounts)} accounts")
    
    def add_account(self, account: EmailAccount):
        """Add or update an email account."""
        self.accounts[account.email] = account
        self.save_accounts()
    
    def remove_account(self, email: str):
        """Remove an email account."""
        if email in self.accounts:
            del self.accounts[email]
            self.save_accounts()
    
    def get_account(self, email: str) -> Optional[EmailAccount]:
        """Get an account by email address."""
        return self.accounts.get(email)
    
    def save_accounts(self):
        """Save all accounts to configuration file with proper Exchange handling."""
        try:
            config = {}
            for email, account in self.accounts.items():
                account_data = {
                    'account_type': account.account_type,
                    'email': account.email,
                    'signature': account.signature,
                    'provider_settings': {}
                }
                
                # Save provider-specific settings
                if isinstance(account.provider, SMTPProvider):
                    account_data['provider_settings'] = {
                        'smtp_server': account.provider.smtp_server,
                        'smtp_port': account.provider.smtp_port,
                        'imap_server': account.provider.imap_server,
                        'imap_port': account.provider.imap_port,
                        'use_tls': account.provider.use_tls,
                        'password': self.secure_storage.encrypt(account.provider.password)
                    }
                elif isinstance(account.provider, GmailProvider):
                    account_data['provider_settings'] = {
                        'credentials_path': account.provider.credentials_path
                    }
                elif isinstance(account.provider, ExchangeProvider):
                    account_data['provider_settings'] = {
                        'client_id': account.provider.client_id,
                        'email': account.provider.email
                    }
                
                config[email] = account_data
                
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
                
        except Exception as e:
            error_msg = f"Failed to save accounts: {str(e)}"
            print(error_msg)
            messagebox.showerror("Error", error_msg)

    def load_accounts(self):
        """Load accounts from configuration file with Exchange support."""
        if not os.path.exists(self.config_file):
            print("No account configuration file found")
            return
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                
            for email, account_data in config.items():
                try:
                    provider_settings = account_data.get('provider_settings', {})
                    
                    if account_data['account_type'] == 'gmail':
                        provider = GmailProvider()
                        if 'credentials_path' in provider_settings:
                            try:
                                provider.authenticate(provider_settings['credentials_path'])
                            except Exception as auth_error:
                                print(f"Failed to authenticate Gmail account {email}: {auth_error}")
                                continue
                                
                    elif account_data['account_type'] == 'smtp':
                        encrypted_password = provider_settings.get('password', '')
                        if not encrypted_password:
                            print(f"No password found for SMTP account {email}")
                            continue
                            
                        password = self.secure_storage.decrypt(encrypted_password)
                        provider = SMTPProvider(
                            email=account_data['email'],
                            password=password,
                            smtp_server=provider_settings['smtp_server'],
                            smtp_port=provider_settings['smtp_port'],
                            imap_server=provider_settings.get('imap_server'),
                            imap_port=provider_settings.get('imap_port'),
                            use_tls=provider_settings.get('use_tls', True)
                        )
                        
                        try:
                            provider.authenticate()
                        except Exception as auth_error:
                            print(f"Failed to authenticate SMTP account {email}: {auth_error}")
                            continue
    
                    elif account_data['account_type'] == 'exchange':
                        client_id = provider_settings.get('client_id')
                        if not client_id:
                            print(f"No client ID found for Exchange account {email}")
                            continue
    
                        provider = ExchangeProvider()
                        # Try silent authentication first
                        try:
                            if provider.authenticate(client_id, force_auth=False):
                                account = EmailAccount(
                                    account_type=account_data['account_type'],
                                    email=account_data['email'],
                                    provider=provider,
                                    signature=account_data.get('signature', '')
                                )
                                self.accounts[email] = account
                                print(f"Successfully loaded account: {email}")
                            else:
                                print(f"Will defer authentication for Exchange account: {email}")
                        except Exception as auth_error:
                            print(f"Will defer authentication for Exchange account: {email}")
                            continue
    
                    else:
                        print(f"Unknown account type for {email}: {account_data['account_type']}")
                        continue
                    
                    account = EmailAccount(
                        account_type=account_data['account_type'],
                        email=account_data['email'],
                        provider=provider,
                        signature=account_data.get('signature', '')
                    )
                    self.accounts[email] = account
                    print(f"Successfully loaded account: {email}")
                    
                except Exception as e:
                    print(f"Error loading account {email}: {e}")
                    continue
            
            print(f"Loaded {len(self.accounts)} accounts successfully")
            
        except Exception as e:
            error_msg = f"Error loading account configuration: {e}"
            print(error_msg)
            self.accounts = {}
            raise Exception(error_msg)
    
    def validate_email(self, email: str) -> bool:
        """Validate email address format."""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email.strip()))
