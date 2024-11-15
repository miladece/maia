import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import webbrowser
import json
import threading
from typing import Dict, Optional, Callable

from ..models import EmailAccount, AccountManager
from ..email_providers import GmailProvider, ExchangeProvider, SMTPProvider


class ConfigWindow:
    def __init__(self, parent, config_manager, callback):
        self.window = tk.Toplevel(parent)
        self.window.title("Configuration")
        self.window.geometry("500x400")
        self.config_manager = config_manager
        self.callback = callback
        
        self.assistants = {}
        self.create_widgets()
        self.load_existing_config()

    def create_widgets(self):
        ttk.Label(self.window, text="OpenAI API Key:").pack(padx=10, pady=5)
        self.api_key_entry = ttk.Entry(self.window, width=50)
        self.api_key_entry.pack(padx=10, pady=5)

        ttk.Label(self.window, text="Assistants:").pack(padx=10, pady=5)
        self.assistants_frame = ttk.Frame(self.window)
        self.assistants_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        self.add_assistant_button = ttk.Button(self.window, text="Add Assistant", 
                                             command=self.add_assistant_row)
        self.add_assistant_button.pack(pady=5)

        ttk.Button(self.window, text="Save", command=self.save_config).pack(pady=20)

    def load_existing_config(self):
        config = self.config_manager.config
        self.api_key_entry.insert(0, config.get('openai_api_key', ''))
        for name, assistant_id in config.get('assistants', {}).items():
            self.add_assistant_row(name, assistant_id)

    def add_assistant_row(self, name='', assistant_id=''):
        row = ttk.Frame(self.assistants_frame)
        row.pack(fill=tk.X, pady=2)

        name_entry = ttk.Entry(row, width=20)
        name_entry.insert(0, name)
        name_entry.pack(side=tk.LEFT, padx=2)

        id_entry = ttk.Entry(row, width=40)
        id_entry.insert(0, assistant_id)
        id_entry.pack(side=tk.LEFT, padx=2)

        ttk.Button(row, text="Remove", 
                  command=lambda: self.remove_assistant_row(row)).pack(side=tk.LEFT, padx=2)

        self.assistants[row] = (name_entry, id_entry)

    def remove_assistant_row(self, row):
        row.destroy()
        del self.assistants[row]

    def save_config(self):
        api_key = self.api_key_entry.get().strip()
        assistants = {
            name_entry.get().strip(): id_entry.get().strip() 
            for name_entry, id_entry in self.assistants.values()
            if name_entry.get().strip() and id_entry.get().strip()
        }
        
        if not api_key:
            messagebox.showerror("Error", "API Key is required!")
            return

        if not assistants:
            messagebox.showerror("Error", "At least one assistant is required!")
            return

        self.config_manager.save_config(api_key, assistants)
        self.callback(api_key, assistants)
        self.window.destroy()
        messagebox.showinfo("Success", "Configuration saved successfully!")

class AccountDialog:
    def __init__(self, parent, account_manager, account=None):
        self.window = tk.Toplevel(parent)
        self.window.title("Account Configuration")
        self.window.geometry("500x650")
        
        self.account_manager = account_manager
        self.account = account
        self.provider = None
        
        # Update account types to include Exchange
        self.account_types = ["Gmail", "Exchange", "SMTP"]
        
        self.create_widgets()
        if account:
            self.load_account_data()

    def save_exchange_account(self, email, signature):
        """Save Exchange account with the new authentication flow"""
        client_id = self.client_id_entry.get().strip()
        if not client_id:
            raise ValueError("Client ID is required")
    
        provider = ExchangeProvider()
        try:
            if provider.authenticate(client_id):
                account = EmailAccount("exchange", email, provider, signature)
                self.account_manager.add_account(account)
            else:
                raise ValueError("Authentication failed")
        except Exception as auth_error:
            raise ValueError(f"Authentication failed: {str(auth_error)}")

    def create_widgets(self):
        # Account type selection
        type_frame = ttk.LabelFrame(self.window, text="Account Type")
        type_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(type_frame, text="Select Account Type:").pack(pady=5)
        self.account_type = ttk.Combobox(
            type_frame,
            values=self.account_types,
            state="readonly"
        )
        self.account_type.pack(pady=5)
        self.account_type.bind("<<ComboboxSelected>>", self.on_account_type_changed)
        
        # Email address
        email_frame = ttk.LabelFrame(self.window, text="Email Address")
        email_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(email_frame, text="Email:").pack(pady=5)
        self.email_entry = ttk.Entry(email_frame, width=40)
        self.email_entry.pack(pady=5)
        
        # Provider settings frame
        self.provider_frame = ttk.LabelFrame(self.window, text="Provider Settings")
        self.provider_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Signature
        signature_frame = ttk.LabelFrame(self.window, text="Email Signature (HTML)")
        signature_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.signature_text = tk.Text(signature_frame, height=4)
        self.signature_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Test Connection",
                  command=self.test_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save", 
                  command=self.save_account).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel",
                  command=self.window.destroy).pack(side=tk.LEFT, padx=5)
        
        # Set default account type
        self.account_type.set("SMTP")
        self.on_account_type_changed(None)

    def on_account_type_changed(self, event):
        """Handle account type selection change"""
        for widget in self.provider_frame.winfo_children():
            widget.destroy()
            
        account_type = self.account_type.get().lower()
        
        if account_type == "exchange":
            self.create_exchange_settings()
        elif account_type == "smtp":
            self.create_smtp_settings()
        elif account_type == "gmail":
            self.create_gmail_settings()

    def create_exchange_settings(self):
        """Create Exchange-specific settings with updated instructions"""
        frame = ttk.Frame(self.provider_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
        # Create two columns
        left_column = ttk.Frame(frame)
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        right_column = ttk.Frame(frame)
        right_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
    
        # Left column - Instructions
        instructions_frame = ttk.LabelFrame(left_column, text="Setup Instructions")
        instructions_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    
        instructions = (
            "1. Azure Portal Setup:\n"
            "   • Go to Azure Portal > App Registrations\n"
            "   • Create New Registration\n"
            "   • Select 'Personal Microsoft accounts only'\n"
            "   • Set Redirect URI: http://localhost\n"
            "   • Enable public client flows\n\n"
            "2. API Permissions:\n"
            "   • Add Microsoft Graph permissions:\n"
            "   • Mail.Read\n"
            "   • Mail.ReadBasic\n"
            "   • Mail.Send (Required for sending)\n"
            "   • User.Read\n\n"
            "3. After adding permissions:\n"
            "   • Click 'Grant admin consent'\n"
            "   • Save changes\n\n"
            "4. Authentication:\n"
            "   • Copy Application (client) ID\n"
            "   • Paste ID in the field to the right\n"
            "   • Click 'Test Connection'\n"
            "   • Follow the authentication steps"
        )
    
        ttk.Label(
            instructions_frame,
            text=instructions,
            wraplength=250,
            justify="left"
        ).pack(pady=10, padx=10, anchor="w")
    
        ttk.Button(
            instructions_frame,
            text="Open Azure Portal",
            command=lambda: webbrowser.open("https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps")
        ).pack(pady=5)
    
        # Right column - Configuration
        config_frame = ttk.LabelFrame(right_column, text="Configuration")
        config_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    
        ttk.Label(config_frame, text="Application (Client) ID:").pack(pady=5)
        self.client_id_entry = ttk.Entry(config_frame, width=40)
        self.client_id_entry.pack(pady=5)
    
        # Authentication status display
        status_frame = ttk.LabelFrame(config_frame, text="Authentication Status")
        status_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.auth_status = tk.Text(
            status_frame,
            height=8,  # Increased height
            width=35,
            wrap=tk.WORD,
            font=("Courier", 9)
        )
        self.auth_status.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        self.auth_status.insert("1.0", "Click 'Test Connection' to start authentication...")
        self.auth_status.config(state="disabled")
    
        # Add scrollbar to status text
        status_scroll = ttk.Scrollbar(status_frame, command=self.auth_status.yview)
        status_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.auth_status.config(yscrollcommand=status_scroll.set)


    def _update_status_text(self, message):
        """Update the status text widget"""
        try:
            self.auth_status.config(state="normal")
            self.auth_status.delete("1.0", tk.END)
            self.auth_status.insert("1.0", message)
            self.auth_status.see(tk.END)  # Scroll to bottom
            self.auth_status.config(state="disabled")
            self.window.update_idletasks()  # Force UI update
        except Exception as e:
            print(f"Error updating status: {e}")

    def _authentication_success(self):
        """Handle successful authentication"""
        self._update_status_text("Authentication successful!")
        messagebox.showinfo("Success", "Connection test successful!")

    def _authentication_failed(self, error_message):
        """Handle failed authentication"""
        self._update_status_text(f"Authentication failed: {error_message}")
        messagebox.showerror("Error", f"Authentication failed: {error_message}")    

    def create_smtp_settings(self):
        """Create SMTP settings UI with presets and improved instructions"""
        # Quick Setup Buttons
        presets_frame = ttk.LabelFrame(self.provider_frame, text="Quick Setup")
        presets_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Help text
        ttk.Label(presets_frame, 
                 text="Select your email provider for automatic configuration:",
                 wraplength=400).pack(pady=5)
        
        presets = {
            "Gmail": {
                "smtp": "smtp.gmail.com",
                "smtp_port": "587",
                "imap": "imap.gmail.com",
                "imap_port": "993",
                "use_tls": True,
                "instructions": (
                    "Gmail requires an App Password:\n\n"
                    "1. Go to Google Account Settings\n"
                    "2. Enable 2-Step Verification\n"
                    "3. Go to Security > App Passwords\n"
                    "4. Generate new App Password for Mail"
                ),
                "link": "https://myaccount.google.com/apppasswords"
            },
            "Outlook/Hotmail": {
                "smtp": "smtp-mail.outlook.com",  # Updated server address
                "smtp_port": "587",
                "imap": "outlook.office365.com",
                "imap_port": "993",
                "use_tls": True,
                "instructions": (
                    "Important: Outlook/Hotmail requires an App Password!\n\n"
                    "1. Go to Microsoft Account Security\n"
                    "2. Enable 2-Step Verification if not enabled\n"
                    "3. Look for 'App passwords' option\n"
                    "4. Create a new App Password for 'Mail'\n"
                    "5. Copy the 16-character password exactly\n"
                    "6. Paste it here (no spaces)\n\n"
                    "Note: Regular account password will not work."
                ),
                "link": "https://account.microsoft.com/security"
            },
            "Yahoo": {
                "smtp": "smtp.mail.yahoo.com",
                "smtp_port": "587",
                "imap": "imap.mail.yahoo.com",
                "imap_port": "993",
                "use_tls": True,
                "instructions": (
                    "Yahoo Mail requires an App Password:\n\n"
                    "1. Go to Yahoo Account Security\n"
                    "2. Enable 2-Step Verification if not enabled\n"
                    "3. Generate app password for Mail\n"
                    "4. Use that App Password here"
                ),
                "link": "https://login.yahoo.com/account/security"
            },
            "Custom": {
                "smtp": "",
                "smtp_port": "587",
                "imap": "",
                "imap_port": "993",
                "use_tls": True,
                "instructions": (
                    "Enter your email server settings:\n\n"
                    "• SMTP and IMAP server addresses\n"
                    "• Port numbers (usually 587 for SMTP, 993 for IMAP)\n"
                    "• Enable TLS if your server requires it\n"
                    "• Use your email credentials"
                ),
                "link": None
            }
        }
        
        def apply_preset(preset_name):
            settings = presets.get(preset_name)
            if settings:
                # Clear and set new values
                self.smtp_server.delete(0, tk.END)
                self.smtp_server.insert(0, settings["smtp"])
                self.smtp_port.delete(0, tk.END)
                self.smtp_port.insert(0, settings["smtp_port"])
                self.imap_server.delete(0, tk.END)
                self.imap_server.insert(0, settings["imap"])
                self.imap_port.delete(0, tk.END)
                self.imap_port.insert(0, settings["imap_port"])
                self.use_tls.set(settings["use_tls"])
                
                # Update instructions
                for widget in info_frame.winfo_children():
                    widget.destroy()
                
                # Add instructions with proper wrapping
                if settings["instructions"]:
                    instruction_label = ttk.Label(
                        info_frame,
                        text=settings["instructions"],
                        wraplength=350,
                        justify=tk.LEFT
                    )
                    instruction_label.pack(pady=5, padx=5, anchor="w")
                
                # Add setup link button if available
                if settings["link"]:
                    link_btn = ttk.Button(
                        info_frame,
                        text="Open Setup Page",
                        command=lambda: webbrowser.open(settings["link"])
                    )
                    link_btn.pack(pady=5)
        
        # Create buttons frame for presets
        buttons_frame = ttk.Frame(presets_frame)
        buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create buttons for each preset
        for name in presets:
            ttk.Button(
                buttons_frame,
                text=name,
                command=lambda n=name: apply_preset(n)
            ).pack(side=tk.LEFT, padx=2)
        
        # Create frame for instructions
        info_frame = ttk.Frame(presets_frame)
        info_frame.pack(fill=tk.X, pady=5)
        
        # Server Settings
        settings_frame = ttk.LabelFrame(self.provider_frame, text="Server Settings")
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create two columns for SMTP and IMAP settings
        smtp_frame = ttk.LabelFrame(settings_frame, text="SMTP Settings")
        smtp_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 2))
        
        ttk.Label(smtp_frame, text="SMTP Server:").pack(pady=2)
        self.smtp_server = ttk.Entry(smtp_frame)
        self.smtp_server.pack(pady=2, padx=5, fill=tk.X)
        
        ttk.Label(smtp_frame, text="SMTP Port:").pack(pady=2)
        self.smtp_port = ttk.Entry(smtp_frame)
        self.smtp_port.insert(0, "587")
        self.smtp_port.pack(pady=2, padx=5)
        
        # IMAP Settings
        imap_frame = ttk.LabelFrame(settings_frame, text="IMAP Settings")
        imap_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(2, 0))
        
        ttk.Label(imap_frame, text="IMAP Server:").pack(pady=2)
        self.imap_server = ttk.Entry(imap_frame)
        self.imap_server.pack(pady=2, padx=5, fill=tk.X)
        
        ttk.Label(imap_frame, text="IMAP Port:").pack(pady=2)
        self.imap_port = ttk.Entry(imap_frame)
        self.imap_port.insert(0, "993")
        self.imap_port.pack(pady=2, padx=5)
        
        # Authentication frame
        auth_frame = ttk.LabelFrame(self.provider_frame, text="Authentication")
        auth_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Username/Email
        ttk.Label(auth_frame, text="Email:").pack(pady=2)
        self.smtp_username = ttk.Entry(auth_frame, width=40)
        self.smtp_username.pack(pady=2)
        
        # Password field
        ttk.Label(auth_frame, text="Password/App Password:").pack(pady=2)
        self.smtp_password = ttk.Entry(auth_frame, show="*", width=40)
        self.smtp_password.pack(pady=2)
        
        # TLS option
        self.use_tls = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            auth_frame,
            text="Use TLS (recommended)",
            variable=self.use_tls
        ).pack(pady=5)
        
        # Add help text about App Passwords
        ttk.Label(
            auth_frame,
            text="Note: Many providers require App Passwords when 2FA is enabled.",
            wraplength=350,
            foreground="dark gray"
        ).pack(pady=5)

    def create_gmail_settings(self):
        ttk.Label(self.provider_frame, text="Gmail Setup Instructions:", 
                 font=("Arial", 10, "bold")).pack(pady=5)
        ttk.Label(self.provider_frame, text="1. Go to Google Cloud Console").pack(pady=2)
        ttk.Label(self.provider_frame, text="2. Create a new project or select existing").pack(pady=2)
        ttk.Label(self.provider_frame, text="3. Enable Gmail API").pack(pady=2)
        ttk.Label(self.provider_frame, text="4. Create OAuth 2.0 Client ID").pack(pady=2)
        ttk.Label(self.provider_frame, text="5. Download credentials").pack(pady=2)
        
        ttk.Label(self.provider_frame, text="Client Configuration File:").pack(pady=5)
        self.credentials_path = ttk.Entry(self.provider_frame, width=40)
        self.credentials_path.pack(pady=5)
        
        ttk.Button(self.provider_frame, text="Browse",
                  command=self.browse_credentials).pack(pady=5)
        
        link_label = ttk.Label(self.provider_frame, 
                           text="Open Google Cloud Console",
                           foreground="blue", cursor="hand2")
        link_label.pack(pady=5)
        link_label.bind("<Button-1>", 
                       lambda e: self.open_url("https://console.cloud.google.com"))

    def browse_credentials(self):
        filename = filedialog.askopenfilename(
            title="Select credentials file",
            filetypes=[("JSON files", "*.json")]
        )
        if filename:
            self.credentials_path.delete(0, tk.END)
            self.credentials_path.insert(0, filename)

    def test_connection(self):
        """Test connection with improved error handling and user feedback"""
        try:
            account_type = self.account_type.get().lower()
            
            if account_type == "smtp":
                # Validate fields
                email = self.smtp_username.get().strip()
                if not email:
                    raise ValueError("Email address is required")
                    
                password = self.smtp_password.get().strip()
                if not password:
                    raise ValueError("Password is required")
                    
                smtp_server = self.smtp_server.get().strip()
                if not smtp_server:
                    raise ValueError("SMTP server address is required")
                    
                smtp_port = self.smtp_port.get().strip()
                if not smtp_port:
                    raise ValueError("SMTP port is required")
                smtp_port = int(smtp_port)
                
                # Get IMAP settings if provided
                imap_server = self.imap_server.get().strip()
                imap_port = self.imap_port.get().strip()
                if imap_server and imap_port:
                    imap_port = int(imap_port)
                else:
                    imap_server = None
                    imap_port = None
                    
                use_tls = self.use_tls.get()
                
                # Create provider instance
                provider = SMTPProvider(
                    email=email,
                    password=password,
                    smtp_server=smtp_server,
                    smtp_port=smtp_port,
                    imap_server=imap_server,
                    imap_port=imap_port,
                    use_tls=use_tls
                )
                
                # Test authentication and connections
                if provider.authenticate():
                    # Build success message
                    success_parts = []
                    success_parts.append("✓ SMTP Connection Successful")
                    
                    if provider.imap:
                        success_parts.append("✓ IMAP Connection Successful")
                    
                    success_message = (
                        "Connection test successful!\n\n"
                        f"{'\n'.join(success_parts)}\n\n"
                        f"Server: {smtp_server}\n"
                        f"Protocol: {'TLS' if use_tls else 'No TLS'}\n"
                        f"Account: {email}\n"
                    )
                    
                    if provider.is_outlook:
                        success_message += (
                            "\nNote: Your Outlook account is properly configured with "
                            "App Password authentication."
                        )
                    
                    messagebox.showinfo("Success", success_message)
                    return True
                
            elif account_type == "gmail":
                credentials_path = self.credentials_path.get().strip()
                if not credentials_path:
                    raise ValueError("Credentials file path is required")
                
                provider = GmailProvider()
                if provider.authenticate(credentials_path):
                    messagebox.showinfo(
                        "Success", 
                        "Gmail authentication successful!\nOAuth2 credentials are valid."
                    )
                    return True

            elif account_type == "exchange":
                client_id = self.client_id_entry.get().strip()
                if not client_id:
                    raise ValueError("Client ID is required")
    
                # Clear and enable status display
                def update_status(message):
                    self.window.after(0, self._update_status_text, message)
    
                # Create and configure provider
                provider = ExchangeProvider()
                provider.set_status_callback(update_status)
                self.provider = provider  # Store provider instance
    
                def authenticate_async():
                    try:
                        if provider.authenticate(client_id):
                            # Update email field with retrieved email
                            if provider.email:
                                self.window.after(0, lambda: self.email_entry.delete(0, tk.END))
                                self.window.after(0, lambda: self.email_entry.insert(0, provider.email))
                            self.window.after(0, self._authentication_success)
                    except Exception as e:
                        self.window.after(0, self._authentication_failed, str(e))
    
                # Start authentication in separate thread
                self._update_status_text("Starting authentication process...")
                threading.Thread(target=authenticate_async, daemon=True).start()
                return True
                    
        except ValueError as ve:
            messagebox.showerror("Validation Error", str(ve))
            return False
            
        except Exception as e:
            error_msg = str(e)
            
            if "certificate" in error_msg.lower():
                error_msg = (
                    "SSL Certificate verification failed.\n\n"
                    "This is often normal with Outlook/Office365 connections.\n"
                    "The connection is still secure and you can proceed to save the account.\n\n"
                    "Technical details:\n"
                    "A fallback SSL configuration will be used to maintain compatibility."
                )
            elif "timeout" in error_msg.lower():
                error_msg = (
                    "Connection timed out.\n\n"
                    "Please check:\n"
                    "1. Your internet connection\n"
                    "2. Server addresses are correct\n"
                    "3. Ports are not blocked by your firewall\n"
                    "4. Server is not experiencing issues"
                )
            elif "5.7.139" in error_msg:
                error_msg = (
                    "Outlook requires an App Password for this connection.\n\n"
                    "To fix this:\n"
                    "1. Go to your Microsoft Account Security settings\n"
                    "2. Enable 2-Factor Authentication if not already enabled\n"
                    "3. Generate an App Password specifically for Mail\n"
                    "4. Use that App Password instead of your regular password\n\n"
                    "Would you like to open the Microsoft Account Security page?"
                )
                if messagebox.askyesno("Authentication Error", error_msg):
                    webbrowser.open("https://account.microsoft.com/security")
                return False
                
            messagebox.showerror("Connection Test Failed", error_msg)
            return False

    def open_url(self, url):
        import webbrowser
        webbrowser.open(url)

    def load_account_data(self):
        if not self.account:
            return
            
        # Set basic fields
        self.account_type.set(self.account.account_type.capitalize())
        self.email_entry.insert(0, self.account.email)
        
        if self.account.signature:
            self.signature_text.insert("1.0", self.account.signature)
        
        # Load provider-specific settings
        provider = self.account.provider
        if isinstance(provider, SMTPProvider):
            if hasattr(self, 'smtp_server'):
                self.smtp_server.delete(0, tk.END)
                self.smtp_server.insert(0, provider.smtp_server)
                self.smtp_port.delete(0, tk.END)
                self.smtp_port.insert(0, str(provider.smtp_port))
                self.imap_server.delete(0, tk.END)
                self.imap_server.insert(0, provider.imap_server)
                self.imap_port.delete(0, tk.END)
                self.imap_port.insert(0, str(provider.imap_port))
                self.smtp_username.delete(0, tk.END)
                self.smtp_username.insert(0, provider.email)
                self.use_tls.set(provider.use_tls)
        elif isinstance(provider, GmailProvider):
            if hasattr(self, 'credentials_path'):
                self.credentials_path.delete(0, tk.END)
                self.credentials_path.insert(0, provider.credentials_path)

    def save_account(self):
        """Save account with improved validation and Exchange support"""
        try:
            email = self.email_entry.get().strip()
            if not email:
                raise ValueError("Email is required")
            
            account_type = self.account_type.get().lower()
            signature = self.signature_text.get("1.0", tk.END).strip()
            
            if account_type == "exchange":
                if not hasattr(self, 'provider') or not self.provider or not self.provider.access_token:
                    raise ValueError("Please test the connection first")
                    
                if not self.provider.email:
                    raise ValueError("Could not retrieve email address from Microsoft account")
                    
                # Create account using the authenticated provider
                account = EmailAccount("exchange", email, self.provider, signature)
                self.account_manager.add_account(account)
                self.account_manager.save_accounts()  # Explicitly save accounts
                self.window.destroy()
                messagebox.showinfo("Success", "Account saved successfully!")
                
            elif account_type == "smtp":
                self.save_smtp_account(email, signature)
            elif account_type == "gmail":
                self.save_gmail_account(email, signature)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save account: {str(e)}")

    def save_smtp_account(self, email, signature):
            """Save SMTP account configuration."""
            try:
                password = self.smtp_password.get().strip()
                if not password:
                    raise ValueError("Password is required")
                
                provider = SMTPProvider(
                    email=self.smtp_username.get().strip(),
                    password=password,
                    smtp_server=self.smtp_server.get().strip(),
                    smtp_port=int(self.smtp_port.get().strip()),
                    imap_server=self.imap_server.get().strip(),
                    imap_port=int(self.imap_port.get().strip()),
                    use_tls=self.use_tls.get()
                )
                
                try:
                    provider.authenticate()
                    self.provider = provider
                except Exception as auth_error:
                    raise ValueError(f"Authentication failed: {str(auth_error)}")
                
                account = EmailAccount("smtp", email, provider, signature)
                self.account_manager.add_account(account)
                self.window.destroy()
                messagebox.showinfo("Success", "Account saved successfully!")
                
            except ValueError as ve:
                messagebox.showerror("Error", str(ve))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save account: {str(e)}")

    def save_gmail_account(self, email, signature):
        credentials_path = self.credentials_path.get().strip()
        if not credentials_path:
            raise ValueError("Credentials file is required")
        
        provider = GmailProvider()
        try:
            provider.authenticate(credentials_path)
            self.provider = provider
        except Exception as auth_error:
            raise ValueError(f"Authentication failed: {str(auth_error)}")
        
        account = EmailAccount("gmail", email, provider, signature)
        self.account_manager.add_account(account)
        self.window.destroy()
        messagebox.showinfo("Success", "Account saved successfully!")

class AccountConfigWindow:
    def __init__(self, parent, account_manager, callback=None):
        self.window = tk.Toplevel(parent)
        self.window.title("Email Accounts")
        self.window.geometry("600x400")
        
        self.account_manager = account_manager
        self.callback = callback
        self.create_widgets()

    def create_widgets(self):
        # Account list frame
        list_frame = ttk.LabelFrame(self.window, text="Configured Accounts")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create Treeview for accounts
        self.account_list = ttk.Treeview(list_frame, 
                                       columns=("Email", "Type", "Provider"),
                                       show="headings")
        self.account_list.heading("Email", text="Email")
        self.account_list.heading("Type", text="Account Type")
        self.account_list.heading("Provider", text="Provider")
        
        # Configure column widths
        self.account_list.column("Email", width=250)
        self.account_list.column("Type", width=100)
        self.account_list.column("Provider", width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical",
                                command=self.account_list.yview)
        self.account_list.configure(yscrollcommand=scrollbar.set)
        
        # Pack list and scrollbar
        self.account_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons frame
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Add Account",
                  command=self.show_add_account_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit Account",
                  command=self.edit_selected_account).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Remove Account",
                  command=self.remove_selected_account).pack(side=tk.LEFT, padx=5)
        
        self.refresh_account_list()

    def refresh_account_list(self):
        """Refresh account list with proper provider display"""
        # Clear existing items
        for item in self.account_list.get_children():
            self.account_list.delete(item)
        
        # Add accounts to the list
        for email, account in self.account_manager.accounts.items():
            if isinstance(account.provider, ExchangeProvider):
                provider_type = "Microsoft Exchange"
            elif hasattr(account.provider, 'smtp_server'):
                provider_type = f"SMTP ({account.provider.smtp_server})"
            else:
                provider_type = account.account_type.upper()
                
            self.account_list.insert("", "end", values=(
                email,
                account.account_type.upper(),
                provider_type
            ))

    def show_add_account_dialog(self):
        dialog = AccountDialog(self.window, self.account_manager)
        self.window.wait_window(dialog.window)
        self.refresh_account_list()
        if self.callback:
            self.callback()

    def edit_selected_account(self):
        selected = self.account_list.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an account to edit")
            return
        
        email = self.account_list.item(selected[0])["values"][0]
        account = self.account_manager.get_account(email)
        if account:
            dialog = AccountDialog(self.window, self.account_manager, account)
            self.window.wait_window(dialog.window)
            self.refresh_account_list()
            if self.callback:
                self.callback()

    def remove_selected_account(self):
        selected = self.account_list.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an account to remove")
            return
        
        email = self.account_list.item(selected[0])["values"][0]
        if messagebox.askyesno("Confirm", f"Are you sure you want to remove {email}?"):
            self.account_manager.remove_account(email)
            self.refresh_account_list()
            if self.callback:
                self.callback()        
