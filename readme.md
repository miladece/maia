# Maia Mail Assistant v1.7.3

An AI-powered email assistant that helps manage and respond to emails using various email providers (Gmail, Exchange, SMTP).

## Features

- Support for multiple email providers (Gmail, Microsoft Exchange, SMTP)
- AI-powered email response generation using OpenAI
- Email preview and formatting
- Secure credential storage
- User-friendly configuration interface

## Prerequisites

- Python 3.8 or higher
- OpenAI API key
- Email provider credentials (varies by provider)

## Installation

1. Unzip the folder.  

2. Make sure you're in the project root directory.  
cd /path/to/maia_email_assistant     

3. Create a new virtual environment  
python3 -m venv venv  

4. Activate the virtual environment  
source venv/bin/activate  

5. Upgrade pip  
pip install --upgrade pip  

6. Install the package in editable mode  
pip install -e .  

7. Try running the application  
python -m maia_mail_assistant.main


## Configuration

1. First-time setup will prompt for:
   - OpenAI API key
   - Assistant configuration
   - Email account setup

2. Email Provider Setup:
   - Gmail: Requires OAuth 2.0 credentials from Google Cloud Console
   - Exchange: Requires Azure Application registration via https://entra.microsoft.com/
   - SMTP: Requires email server details and credentials


## Author

Miguel Ladron de Cegama
https://www.unmannedexpert.com

## License

[License Type] - See LICENSE file for details
