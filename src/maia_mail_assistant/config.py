import json
import os
from cryptography.fernet import Fernet
from typing import Dict
from tkinter import messagebox

class SecureStorage:
    """Handles secure storage of sensitive data using Fernet encryption."""
    
    def __init__(self):
        self.key_file = 'email_key.key'
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)
    
    def _load_or_create_key(self) -> bytes:
        """Load existing encryption key or create a new one."""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data."""
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt encrypted string data."""
        return self.fernet.decrypt(encrypted_data.encode()).decode()

class ConfigManager:
    """Manages application configuration including API keys and assistants."""
    
    def __init__(self):
        print("Initializing ConfigManager")
        self.config_file = 'email_assistant_config.json'
        self.config = self.load_config()
        print(f"ConfigManager initialized with config: {self.config}")

    def load_config(self) -> dict:
        """Load configuration with safe defaults."""
        default_config = {
            'openai_api_key': '',
            'assistants': {}
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    if not isinstance(loaded_config, dict):
                        print("Invalid configuration format")
                        return default_config
                        
                    # Ensure all required keys exist
                    for key in default_config:
                        if key not in loaded_config:
                            loaded_config[key] = default_config[key]
                    return loaded_config
            else:
                print("No configuration file found, using defaults")
                return default_config
                
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return default_config

    def save_config(self, openai_api_key: str, assistants: Dict[str, str]):
        """Save configuration with validation."""
        try:
            self.config = {
                'openai_api_key': openai_api_key or '',
                'assistants': assistants or {}
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f)
                
        except Exception as e:
            print(f"Error saving configuration: {e}")
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")
