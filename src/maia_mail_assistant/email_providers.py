from abc import ABC, abstractmethod
import base64
import hashlib
import imaplib
import json
import os
import pickle
import smtplib
import socket
import ssl
import time
import threading
import webbrowser
import email
from datetime import datetime
from email import message_from_bytes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import decode_header
from typing import List, Dict, Optional

import msal
import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

from .gui.widgets import EmailFormatter  # For HTML conversion in email sending

# Set OAuth 2.0 scopes for Gmail
GMAIL_SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.modify'
]

class EmailProvider(ABC):
    """Abstract base class for email providers"""
    
    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with the email service"""
        pass
        
    @abstractmethod
    def send_email(self, to: str, subject: str, body: str, cc: str = None) -> bool:
        """Send an email"""
        pass
        
    @abstractmethod
    def get_emails(self, max_results=20) -> List[Dict]:
        """Fetch emails from the service"""
        pass

class GmailProvider(EmailProvider):
    def __init__(self):
        self.service = None
        self.credentials_path = None
        self.SCOPES = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/gmail.modify'
        ]
        
    def authenticate(self, credentials_path: str) -> bool:
        """Authenticate using Gmail OAuth2 with improved token management"""
        try:
            self.credentials_path = credentials_path
            creds = None
            # Generate a unique token filename based on credentials content
            token_hash = None
            
            try:
                with open(credentials_path, 'r') as f:
                    content = f.read()
                    # Create hash based on client_id from credentials file
                    import json
                    cred_data = json.loads(content)
                    client_id = cred_data['installed']['client_id']
                    token_hash = hashlib.md5(client_id.encode()).hexdigest()
            except Exception as e:
                print(f"Error reading credentials file: {e}")
                token_hash = hashlib.md5(credentials_path.encode()).hexdigest()

            token_dir = 'gmail_tokens'
            if not os.path.exists(token_dir):
                os.makedirs(token_dir)
            
            token_path = os.path.join(token_dir, f'gmail_token_{token_hash}.pickle')
            
            # Try to load existing token
            if os.path.exists(token_path):
                try:
                    with open(token_path, 'rb') as token:
                        creds = pickle.load(token)
                    print(f"Loaded existing token from {token_path}")
                except Exception as e:
                    print(f"Error loading token: {e}")
                    creds = None
            
            # Check if credentials are valid or need refresh
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    print("Refreshing expired token...")
                    creds.refresh(Request())
                else:
                    print("Getting new token...")
                    flow = InstalledAppFlow.from_client_secrets_file(credentials_path, self.SCOPES)
                    creds = flow.run_local_server(port=0)
                
                # Save the token
                try:
                    with open(token_path, 'wb') as token:
                        pickle.dump(creds, token)
                    print(f"Saved new token to {token_path}")
                except Exception as e:
                    print(f"Error saving token: {e}")
            
            self.service = build('gmail', 'v1', credentials=creds)
            return True
            
        except Exception as e:
            raise Exception(f"Gmail authentication failed: {str(e)}")
    
    def get_emails(self, max_results=20) -> List[Dict]:
        """Fetch emails from Gmail"""
        if not self.service:
            raise Exception("Not authenticated with Gmail")
            
        try:
            results = self.service.users().messages().list(
                userId='me', maxResults=max_results).execute()
            messages = results.get('messages', [])
            
            emails_data = []
            for message in messages:
                msg = self.service.users().messages().get(
                    userId='me', id=message['id'], format='full').execute()
                
                headers = msg['payload']['headers']
                email_data = {
                    'id': message['id'],
                    'sender': next((h['value'] for h in headers if h['name'].lower() == 'from'), 'No Sender'),
                    'to': next((h['value'] for h in headers if h['name'].lower() == 'to'), 'No Recipient'),
                    'subject': next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject'),
                    'timestamp': next((h['value'] for h in headers if h['name'].lower() == 'date'), None),
                    'body': self._get_email_body(msg)
                }
                emails_data.append(email_data)
                
            return emails_data
            
        except Exception as e:
            raise Exception(f"Failed to fetch emails: {str(e)}")
    
    def _get_email_body(self, msg):
        """Extract email body from Gmail message"""
        if 'parts' in msg['payload']:
            for part in msg['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    if 'data' in part['body']:
                        return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
        elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
            return base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')
        return ""
    
    def send_email(self, to: str, subject: str, body: str, cc: str = None) -> bool:
        """Send email using Gmail API with both HTML and plain text versions"""
        try:
            message = MIMEMultipart('alternative')
            message['to'] = to
            message['subject'] = subject
            if cc:
                message['cc'] = cc
            
            # Create plain text version
            text_part = MIMEText(body, 'plain', 'utf-8')
            
            # Create HTML version
            html_content = EmailFormatter.markdown_to_html(body)
            html_part = MIMEText(html_content, 'html', 'utf-8')
            
            # Attach both versions
            message.attach(text_part)
            message.attach(html_part)
            
            # Encode the message for Gmail API
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
            
            self.service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            return True
            
        except Exception as e:
            raise Exception(f"Failed to send email: {str(e)}")

class ExchangeProvider(EmailProvider):
    def __init__(self):
        self.access_token = None
        self.SCOPES = [
            "Mail.Read",
            "Mail.ReadBasic",
            "Mail.Send",
            "User.Read"
        ]
        self.client_id = None
        self.email = None
        self.status_callback = None
        self.display_name = "Microsoft Exchange"
        self.token_dir = "exchange_tokens"
        if not os.path.exists(self.token_dir):
            os.makedirs(self.token_dir)

    def _get_token_path(self, client_id: str) -> str:
        """Get the token file path for the given client ID"""
        token_hash = hashlib.md5(client_id.encode()).hexdigest()
        return os.path.join(self.token_dir, f'exchange_token_{token_hash}.json')

    
    def _save_token(self, token_data: dict) -> None:
        """Save token data with encryption"""
        if not self.client_id:
            return
            
        token_path = self._get_token_path(self.client_id)
        try:
            # Add expiration timestamp to token data
            token_data['timestamp'] = time.time()
            with open(token_path, 'w') as f:
                json.dump(token_data, f)
            print(f"Saved token to {token_path}")
        except Exception as e:
            print(f"Error saving token: {e}")

    def _load_token(self) -> dict:
        """Load and validate token data"""
        if not self.client_id:
            return None
            
        token_path = self._get_token_path(self.client_id)
        try:
            if os.path.exists(token_path):
                with open(token_path, 'r') as f:
                    token_data = json.load(f)
                    
                # Check token expiration (default 1 hour for Microsoft tokens)
                timestamp = token_data.get('timestamp', 0)
                if time.time() - timestamp < 3600:  # 1 hour
                    print(f"Loaded valid token from {token_path}")
                    return token_data
                else:
                    print("Token expired, needs refresh")
                    return None
        except Exception as e:
            print(f"Error loading token: {e}")
        return None

    def set_status_callback(self, callback):
        self.status_callback = callback

    def update_status(self, message):
        print(f"Auth Status: {message}")  # Console logging
        if self.status_callback:
            self.status_callback(f"{message}\n")

    def _save_auth_page(self, html_content: str) -> str:
        """Save authentication page to temporary file"""
        import tempfile
        
        fd, path = tempfile.mkstemp(suffix='.html')
        try:
            with os.fdopen(fd, 'w') as tmp:
                tmp.write(html_content)
            return path
        except Exception as e:
            print(f"Error saving auth page: {e}")
            return None

    def authenticate(self, client_id: str, force_auth: bool = False) -> bool:
        """Authenticate using Microsoft Graph API with token persistence"""
        try:
            self.client_id = client_id
            
            if not force_auth:
                # Try to load existing token
                token_data = self._load_token()
                if token_data and 'access_token' in token_data:
                    self.access_token = token_data['access_token']
                    try:
                        # Verify token is still valid
                        if self._verify_token():
                            print("Reusing existing token")
                            return True
                    except:
                        print("Existing token invalid, getting new token")
                        self.access_token = None
            
            # Initialize MSAL app
            app = msal.PublicClientApplication(
                client_id,
                authority="https://login.microsoftonline.com/consumers"
            )

            # Start device flow
            flow = app.initiate_device_flow(scopes=self.SCOPES)
            
            if "user_code" not in flow:
                raise Exception("Could not create device flow")

            # Create and open authentication page
            auth_html = self._create_auth_page(flow['user_code'])
            auth_page_path = self._save_auth_page(auth_html)
            if auth_page_path:
                webbrowser.open('file://' + auth_page_path)

            print(f"Authentication URL: {flow.get('verification_uri')}")
            print(f"Code: {flow.get('user_code')}")

            result = app.acquire_token_by_device_flow(flow)
            
            if "access_token" in result:
                self.access_token = result['access_token']
                self._save_token(result)
                self._get_user_info()
                return True
            else:
                error_msg = result.get('error_description', 'Authentication failed')
                raise Exception(error_msg)

        except Exception as e:
            raise Exception(f"Exchange authentication failed: {str(e)}")

    def _verify_token(self) -> bool:
        """Verify if the current token is still valid"""
        if not self.access_token:
            return False
            
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    

    def _create_auth_page(self, user_code: str) -> str:
        """Create HTML page for authentication"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Microsoft Account Authentication</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    line-height: 1.6;
                    max-width: 600px;
                    margin: 40px auto;
                    padding: 20px;
                    text-align: center;
                    background-color: #f5f5f5;
                }}
                .container {{
                    background-color: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                h1 {{
                    color: #0078d4;
                    margin-bottom: 30px;
                }}
                .code-box {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    border-radius: 4px;
                    margin: 20px 0;
                    font-size: 24px;
                    font-family: monospace;
                    letter-spacing: 2px;
                    cursor: pointer;
                }}
                .instructions {{
                    text-align: left;
                    margin: 20px 0;
                    padding: 20px;
                    background-color: #f0f7ff;
                    border-radius: 4px;
                }}
                .step {{
                    margin: 10px 0;
                    padding-left: 20px;
                }}
                .button {{
                    background-color: #0078d4;
                    color: white;
                    padding: 12px 24px;
                    border: none;
                    border-radius: 4px;
                    text-decoration: none;
                    display: inline-block;
                    margin: 20px 0;
                    font-size: 16px;
                }}
                .button:hover {{
                    background-color: #106ebe;
                }}
                .note {{
                    color: #666;
                    font-size: 14px;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Microsoft Account Authentication</h1>
                
                <div class="instructions">
                    <h2>Follow these steps:</h2>
                    <div class="step">1. Click the button below to open the Microsoft authentication page</div>
                    <div class="step">2. Sign in with your Microsoft account</div>
                    <div class="step">3. When prompted, enter this code:</div>
                </div>

                <div class="code-box" onclick="copyCode()">
                    {user_code}
                    <div style="font-size: 12px; margin-top: 5px;">(Click to copy)</div>
                </div>

                <a href="https://microsoft.com/link" class="button" target="_blank">
                    Open Microsoft Sign-in
                </a>

                <p class="note">
                    After completing the authentication, you can close this window and return to the application.
                    <br>
                    The application will automatically detect when authentication is complete.
                </p>
            </div>

            <script>
                function copyCode() {{
                    navigator.clipboard.writeText('{user_code}').then(function() {{
                        alert('Code copied to clipboard!');
                    }});
                }}
            </script>
        </body>
        </html>
        """
        return html_content
    
    def _show_auth_dialog(self, app):
        """Show authentication dialog with device flow"""
        try:
            # Create device flow with correct scope format
            flow = app.initiate_device_flow(
                scopes=self.SCOPES
            )
            
            if "user_code" not in flow:
                raise Exception("Could not create device flow")

            # Create and show authentication dialog
            auth_window = tk.Toplevel()
            auth_window.title("Microsoft Account Authentication")
            auth_window.geometry("500x400")
            auth_window.grab_set()  # Make window modal
            
            # Center the window
            auth_window.update_idletasks()
            width = auth_window.winfo_width()
            height = auth_window.winfo_height()
            x = (auth_window.winfo_screenwidth() // 2) - (width // 2)
            y = (auth_window.winfo_screenheight() // 2) - (height // 2)
            auth_window.geometry(f'{width}x{height}+{x}+{y}')

            # Authentication instructions
            ttk.Label(
                auth_window,
                text="Microsoft Account Authentication",
                font=("Arial", 14, "bold")
            ).pack(pady=20)

            # Code display
            code_frame = ttk.LabelFrame(auth_window, text="Authentication Code")
            code_frame.pack(padx=20, pady=10, fill="x")
            
            code_text = ttk.Entry(code_frame, font=("Courier", 16))
            code_text.insert(0, flow['user_code'])
            code_text.configure(state="readonly", justify="center")
            code_text.pack(padx=20, pady=10, fill="x")

            def copy_code():
                auth_window.clipboard_clear()
                auth_window.clipboard_append(flow['user_code'])
                copy_button.configure(text="Code Copied!")
                auth_window.after(2000, lambda: copy_button.configure(text="Copy Code"))

            copy_button = ttk.Button(
                code_frame,
                text="Copy Code",
                command=copy_code
            )
            copy_button.pack(pady=5)

            # Instructions
            instructions = ttk.Label(
                auth_window,
                text=(
                    "1. Click the 'Open Browser' button below\n"
                    "2. Sign in to your Microsoft account\n"
                    "3. Enter the code shown above\n"
                    "4. Grant the requested permissions\n"
                    "5. Wait for confirmation"
                ),
                justify="left"
            )
            instructions.pack(pady=20)

            def open_browser():
                webbrowser.open("https://microsoft.com/link")
                browser_button.configure(text="Browser Opened")
                browser_button.configure(state="disabled")

            browser_button = ttk.Button(
                auth_window,
                text="Open Browser",
                command=open_browser
            )
            browser_button.pack(pady=10)

            status_label = ttk.Label(
                auth_window,
                text="Waiting for authentication...",
                font=("Arial", 10)
            )
            status_label.pack(pady=20)

            auth_result = {'success': False}

            def auth_thread():
                try:
                    result = app.acquire_token_by_device_flow(flow)
                    if "access_token" in result:
                        self.access_token = result['access_token']
                        self._save_token(result)  # Save token data
                        self._get_user_info()
                        auth_result['success'] = True
                        auth_window.after(0, auth_window.destroy)
                    else:
                        error_msg = result.get('error_description', 'Authentication failed')
                        auth_window.after(0, lambda: status_label.configure(
                            text=f"Error: {error_msg}",
                            foreground="red"
                        ))
                except Exception as e:
                    auth_window.after(0, lambda: status_label.configure(
                        text=f"Error: {str(e)}",
                        foreground="red"
                    ))

            threading.Thread(target=auth_thread, daemon=True).start()
            auth_window.wait_window()
            return auth_result['success']

        except Exception as e:
            raise Exception(f"Authentication dialog failed: {str(e)}")
  

    def _get_user_info(self):
        """Get user email from Microsoft Graph API"""
        if not self.access_token:
            raise Exception("No access token available")

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 403:
                raise Exception("Permission denied. Please check application permissions in Azure Portal")
            
            response.raise_for_status()
            user_info = response.json()
            
            self.email = user_info.get('userPrincipalName')
            if not self.email:
                raise Exception("Could not retrieve email address from Microsoft account")
                
            print(f"Successfully retrieved user info for: {self.email}")
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get user information: {str(e)}")
        except Exception as e:
            raise Exception(f"Error getting user info: {str(e)}")

    def get_emails(self, max_results=20) -> List[Dict]:
        """Fetch emails using Microsoft Graph API with proper field mapping"""
        if not self.access_token:
            raise Exception("Not authenticated with Exchange")
    
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
    
            # Update select fields to match the API response
            params = {
                '$top': max_results,
                '$select': 'id,subject,from,receivedDateTime,hasAttachments,importance,bodyPreview',
                '$orderby': 'receivedDateTime DESC'
            }
    
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me/messages",
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 403:
                raise Exception("Permission denied. Please check application permissions in Azure Portal")
            
            response.raise_for_status()
            data = response.json()
    
            emails_data = []
            for msg in data.get('value', []):
                try:
                    # Extract sender information
                    sender = msg.get('from', {}).get('emailAddress', {}).get('address', 'Unknown')
                    
                    # Format received date
                    received_date = msg.get('receivedDateTime', '')
                    if received_date:
                        # Convert to datetime object if needed
                        try:
                            received_date = datetime.strptime(
                                received_date, 
                                "%Y-%m-%dT%H:%M:%SZ"
                            ).strftime("%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            # If date parsing fails, use the original string
                            pass
    
                    email_data = {
                        'id': msg.get('id', ''),
                        'subject': msg.get('subject', 'No Subject'),
                        'sender': sender,
                        'timestamp': received_date,  # Use formatted date
                        'has_attachments': msg.get('hasAttachments', False),
                        'importance': msg.get('importance', 'normal'),
                        'body': msg.get('bodyPreview', '')  # Use bodyPreview for initial display
                    }
                    emails_data.append(email_data)
                    
                except Exception as e:
                    print(f"Error processing email message: {e}")
                    continue
    
            print(f"Successfully retrieved {len(emails_data)} emails")
            return emails_data
    
        except Exception as e:
            error_msg = f"Failed to fetch emails: {str(e)}"
            print(error_msg)
            raise Exception(error_msg)  # Fixed missing closing parenthesis here

    def get_email_body(self, email_id: str) -> str:
        """Fetch full email body when needed"""
        if not self.access_token:
            raise Exception("Not authenticated with Exchange")

        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }

            response = requests.get(
                f"https://graph.microsoft.com/v1.0/me/messages/{email_id}",
                headers=headers,
                params={'$select': 'body'},
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            return data.get('body', {}).get('content', '')

        except Exception as e:
            print(f"Error fetching email body: {e}")
            return ""
            
    def send_email(self, to: str, subject: str, body: str, cc: str = None) -> bool:
        """Send email using Microsoft Graph API with improved error handling"""
        if not self.access_token:
            raise Exception("Not authenticated with Exchange")

        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }

            # Convert body to HTML if needed
            html_content = EmailFormatter.markdown_to_html(body)

            # Prepare email message
            message = {
                'message': {
                    'subject': subject,
                    'body': {
                        'contentType': 'HTML',
                        'content': html_content
                    },
                    'toRecipients': [
                        {
                            'emailAddress': {
                                'address': to.strip()
                            }
                        }
                    ]
                },
                'saveToSentItems': True
            }

            # Add CC recipients if provided
            if cc:
                message['message']['ccRecipients'] = [
                    {'emailAddress': {'address': addr.strip()}} 
                    for addr in cc.split(',') if addr.strip()
                ]

            print(f"Attempting to send email to: {to}")
            response = requests.post(
                "https://graph.microsoft.com/v1.0/me/sendMail",
                headers=headers,
                json=message,
                timeout=30
            )

            if response.status_code == 403:
                raise Exception(
                    "Permission denied. Please ensure the Mail.Send permission "
                    "is added in Azure Portal and consent is granted."
                )

            response.raise_for_status()
            print("Email sent successfully")
            return True

        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            if "403" in error_msg:
                print("Permission error - checking token details...")
                try:
                    # Try to get current permissions
                    check_response = requests.get(
                        "https://graph.microsoft.com/v1.0/me",
                        headers=headers
                    )
                    print(f"Current permissions status: {check_response.status_code}")
                except Exception as check_error:
                    print(f"Error checking permissions: {check_error}")
            raise Exception(f"Failed to send email: {error_msg}")
            
        except Exception as e:
            print(f"Error sending email: {e}")
            raise Exception(f"Failed to send email: {str(e)}")

class SMTPProvider(EmailProvider):
    def __init__(self, email: str, password: str, smtp_server: str, smtp_port: int, 
                 imap_server: str = None, imap_port: int = None, use_tls: bool = True):
        self.email = email
        self.password = password
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.imap_server = imap_server
        self.imap_port = imap_port
        self.use_tls = use_tls
        self.smtp = None
        self.imap = None
        self.last_smtp_activity = time.time()
        self.SMTP_TIMEOUT = 120  # 2 minutes timeout
        
        # Detect if this is an Outlook/Hotmail account
        self.is_outlook = any(domain in email.lower() 
                            for domain in ['@outlook.', '@hotmail.', '@live.', '@msn.'])
        
        # Override server settings for Outlook/Office365 if detected
        if self.is_outlook:
            self.smtp_server = 'smtp-mail.outlook.com'
            self.smtp_port = 587
            self.imap_server = 'outlook.office365.com'
            self.imap_port = 993
            self.use_tls = True
        
    
    def _detect_provider(self, email):
        email_lower = email.lower()
        if any(domain in email_lower for domain in ['@outlook.', '@hotmail.', '@live.', '@msn.']):
            return 'outlook'
        elif '@gmail.' in email_lower:
            return 'gmail'
        elif '@yahoo.' in email_lower:
            return 'yahoo'
        return 'other'
    
    def authenticate(self) -> bool:
        """Authenticate both SMTP and IMAP connections"""
        try:
            if self.is_outlook:
                # Create SSL context for Outlook
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Initialize SMTP connection
                self.smtp = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30)
                
                # Start TLS
                self.smtp.ehlo()
                self.smtp.starttls(context=context)
                self.smtp.ehlo()  # Second EHLO after STARTTLS
                
                # Attempt login
                try:
                    self.smtp.login(self.email, self.password)
                except smtplib.SMTPAuthenticationError as e:
                    if "5.7.139" in str(e):
                        raise Exception(
                            "Outlook/Hotmail authentication failed.\n\n"
                            "Please check:\n"
                            "1. You've enabled 2FA in your Microsoft Account\n"
                            "2. You're using an App Password (16 characters)\n"
                            "3. The App Password is specifically for 'Mail'\n\n"
                            "Steps to get App Password:\n"
                            "1. Go to account.microsoft.com/security\n"
                            "2. Enable 2-Step Verification if not enabled\n"
                            "3. Create a new App Password for Mail\n"
                            "4. Copy and use the 16-character password here"
                        )
                    raise
                
                # If SMTP succeeds, try IMAP
                if self.imap_server and self.imap_port:
                    self.imap = imaplib.IMAP4_SSL(self.imap_server, self.imap_port,
                                                 ssl_context=context)
                    self.imap.login(self.email, self.password)
                    
            else:
                # Non-Outlook authentication
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                self.smtp = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30)
                if self.use_tls:
                    self.smtp.starttls(context=context)
                self.smtp.login(self.email, self.password)
                
                if self.imap_server and self.imap_port:
                    self.imap = imaplib.IMAP4_SSL(self.imap_server, self.imap_port,
                                                 ssl_context=context)
                    self.imap.login(self.email, self.password)
            
            return True
            
        except Exception as e:
            # Cleanup on failure
            if self.smtp:
                try:
                    self.smtp.quit()
                except:
                    pass
            if self.imap:
                try:
                    self.imap.logout()
                except:
                    pass
            self.smtp = None
            self.imap = None
            
            # Handle specific Outlook errors
            if self.is_outlook:
                error_msg = str(e)
                if "5.7.139" in error_msg:
                    raise Exception(
                        "Outlook authentication failed.\n\n"
                        "Please verify:\n"
                        "1. You've enabled 2FA in your Microsoft Account\n"
                        "2. You're using an App Password (16 characters)\n"
                        "3. The App Password was generated for 'Mail'\n"
                        "4. You're copying the App Password exactly as shown\n\n"
                        "Common issues:\n"
                        "- Make sure there are no spaces in the App Password\n"
                        "- The App Password should be exactly 16 characters\n"
                        "- Don't use your regular Microsoft account password"
                    )
            raise
            
    def _decode_mime_words(self, text):
        """Decode MIME encoded words in text"""
        try:
            decoded = email.header.decode_header(text)
            parts = []
            for part, charset in decoded:
                if isinstance(part, bytes):
                    if charset:
                        try:
                            parts.append(part.decode(charset))
                        except (UnicodeDecodeError, LookupError):
                            parts.append(part.decode('utf-8', 'replace'))
                    else:
                        parts.append(part.decode('utf-8', 'replace'))
                else:
                    parts.append(str(part))
            return ' '.join(parts)
        except Exception as e:
            print(f"Error decoding MIME words: {e}")
            return text.encode('utf-8', 'replace').decode('utf-8')

    def _decode_text(self, text, default_charset='utf-8'):
        """Decode text with proper charset handling"""
        if isinstance(text, bytes):
            try:
                return text.decode(default_charset, 'replace')
            except:
                return text.decode('utf-8', 'replace')
        return str(text)
    
    def get_emails(self, max_results=20) -> List[Dict]:
        """Fetch emails using IMAP with improved encoding handling"""
        if not self.imap:
            raise Exception("IMAP not configured or authenticated")
            
        try:
            self.imap.select('INBOX')
            _, message_numbers = self.imap.search(None, 'ALL')
            email_ids = message_numbers[0].split()
            
            start_index = max(0, len(email_ids) - max_results)
            email_ids = list(reversed(email_ids[start_index:]))
            
            emails_data = []
            for email_id in email_ids:
                try:
                    _, msg_data = self.imap.fetch(email_id, '(RFC822)')
                    email_body = msg_data[0][1]
                    message = email.message_from_bytes(email_body)
                    
                    # Properly decode headers with MIME word handling
                    subject = self._decode_mime_words(message.get('subject', 'No Subject'))
                    from_header = self._decode_mime_words(message.get('from', 'No Sender'))
                    to_header = self._decode_mime_words(message.get('to', 'No Recipient'))
                    
                    # Get email body
                    body = self._get_email_body(message)
                    if not isinstance(body, str):
                        body = self._decode_text(body)
                    
                    email_data = {
                        'id': email_id.decode(),
                        'sender': from_header,
                        'to': to_header,
                        'subject': subject,
                        'timestamp': message.get('date', ''),
                        'body': body
                    }
                    emails_data.append(email_data)
                    
                except Exception as e:
                    print(f"Error processing email {email_id}: {e}")
                    continue
            
            return emails_data
            
        except Exception as e:
            raise Exception(f"Failed to fetch emails: {str(e)}")
    
    def _get_email_body(self, message) -> str:
        """Extract email body with improved encoding handling"""
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        return payload.decode(charset, 'replace')
                    except Exception as e:
                        print(f"Error decoding multipart: {e}")
                        continue
        else:
            try:
                payload = message.get_payload(decode=True)
                charset = message.get_content_charset() or 'utf-8'
                return payload.decode(charset, 'replace')
            except Exception as e:
                print(f"Error decoding body: {e}")
        return "Could not decode message body"

    def _ensure_smtp_connection(self):
        """Ensure SMTP connection is active and fresh"""
        current_time = time.time()
        
        # Check if connection needs refresh
        if (self.smtp is None or 
            current_time - self.last_smtp_activity > self.SMTP_TIMEOUT):
            try:
                # Close existing connection if any
                if self.smtp:
                    try:
                        self.smtp.quit()
                    except:
                        pass
                    self.smtp = None

                # Create new connection
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                self.smtp = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30)
                
                if self.use_tls:
                    self.smtp.starttls(context=context)
                
                self.smtp.login(self.email, self.password)
                self.last_smtp_activity = current_time
                
            except Exception as e:
                self.smtp = None
                raise Exception(f"Failed to establish SMTP connection: {str(e)}")
    
    def send_email(self, to: str, subject: str, body: str, cc: str = None) -> bool:
        """Send email with connection management and retry logic"""
        max_retries = 2
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Ensure fresh connection
                self._ensure_smtp_connection()
                
                message = MIMEMultipart('alternative')
                message['From'] = self.email
                message['To'] = to
                message['Subject'] = subject
                if cc:
                    message['Cc'] = cc
                
                # Create plain text version
                text_part = MIMEText(body, 'plain', 'utf-8')
                
                # Create HTML version
                html_content = EmailFormatter.markdown_to_html(body)
                html_part = MIMEText(html_content, 'html', 'utf-8')
                
                message.attach(text_part)
                message.attach(html_part)
                
                recipients = [to]
                if cc:
                    recipients.extend(cc.split(','))
                
                # Set timeout for send operation
                self.smtp.sock.settimeout(30)
                
                # Send the email
                self.smtp.send_message(message)
                self.last_smtp_activity = time.time()
                
                return True
                
            except (smtplib.SMTPServerDisconnected, socket.timeout, 
                    smtplib.SMTPResponseException) as e:
                retry_count += 1
                if retry_count >= max_retries:
                    raise Exception(f"Failed to send email after {max_retries} attempts: {str(e)}")
                
                # Reset connection for retry
                try:
                    self.smtp.quit()
                except:
                    pass
                self.smtp = None
                time.sleep(1)  # Brief pause before retry
                
            except Exception as e:
                raise Exception(f"Failed to send email: {str(e)}")
    
    def __del__(self):
        """Cleanup connections"""
        if self.smtp:
            try:
                self.smtp.quit()
            except:
                pass
        if self.imap:
            try:
                self.imap.logout()
            except:
                pass
