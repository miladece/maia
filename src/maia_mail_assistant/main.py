#!/usr/bin/env python
# coding: utf-8

import tkinter as tk
from tkinter import ttk, messagebox
from maia_mail_assistant.config import ConfigManager
from maia_mail_assistant.gui.email_assistant import EmailAssistant

def check_requirements():
    """Check if all required libraries are installed"""
    required_packages = {
        'openai': 'openai',
        'google.oauth2': 'google-auth-oauthlib',
        'google.auth': 'google-auth',
        'googleapiclient': 'google-api-python-client',
        'tkinterweb': 'tkinterweb',
        'cryptography': 'cryptography',
        'markdown': 'markdown'
    }
    
    missing_packages = []
    for module_name, package_name in required_packages.items():
        try:
            __import__(module_name.split('.')[0])
        except ImportError as e:
            print(f"Error importing {module_name}: {str(e)}")
            missing_packages.append(package_name)
    
    if missing_packages:
        message = (
            "The following required packages are missing:\n\n"
            f"{', '.join(missing_packages)}\n\n"
            "Please install them using pip:\n"
            f"pip install {' '.join(missing_packages)}"
        )
        raise ImportError(message)
    
    print("All required packages are installed!")

def show_first_time_setup():
    """Show first-time setup dialog for new users"""
    root = tk.Tk()
    root.withdraw()
    
    setup_window = tk.Toplevel(root)
    setup_window.title("Welcome to Email Assistant")
    setup_window.geometry("500x400")
    
    # Center the window
    setup_window.update_idletasks()
    width = setup_window.winfo_width()
    height = setup_window.winfo_height()
    x = (setup_window.winfo_screenwidth() // 2) - (width // 2)
    y = (setup_window.winfo_screenheight() // 2) - (height // 2)
    setup_window.geometry(f'{width}x{height}+{x}+{y}')
    
    # Welcome message
    ttk.Label(
        setup_window,
        text="Welcome to Email Assistant!",
        font=("Arial", 16, "bold")
    ).pack(pady=20)
    
    ttk.Label(
        setup_window,
        text="Let's get started by setting up your configuration.",
        wraplength=400
    ).pack(pady=10)
    
    # Setup frames
    api_frame = ttk.LabelFrame(setup_window, text="OpenAI Configuration")
    api_frame.pack(fill=tk.X, padx=20, pady=10)
    
    ttk.Label(api_frame, text="OpenAI API Key:").pack(pady=5)
    api_key_entry = ttk.Entry(api_frame, width=50)
    api_key_entry.pack(pady=5)
    
    assistant_frame = ttk.LabelFrame(setup_window, text="Assistant Configuration")
    assistant_frame.pack(fill=tk.X, padx=20, pady=10)
    
    ttk.Label(assistant_frame, text="Assistant Name:").pack(pady=5)
    assistant_name = ttk.Entry(assistant_frame, width=30)
    assistant_name.pack(pady=5)
    
    ttk.Label(assistant_frame, text="Assistant ID:").pack(pady=5)
    assistant_id = ttk.Entry(assistant_frame, width=50)
    assistant_id.pack(pady=5)
    
    def save_initial_config():
        api_key = api_key_entry.get().strip()
        name = assistant_name.get().strip()
        aid = assistant_id.get().strip()
        
        if not all([api_key, name, aid]):
            messagebox.showerror(
                "Error",
                "Please fill in all fields to continue."
            )
            return
            
        config_manager = ConfigManager()
        config_manager.save_config(api_key, {name: aid})
        setup_window.destroy()
        root.destroy()
        
        messagebox.showinfo(
            "Success",
            "Configuration saved successfully! Now let's set up your email account."
        )
    
    ttk.Button(
        setup_window,
        text="Save and Continue",
        command=save_initial_config
    ).pack(pady=20)
    
    root.wait_window(setup_window)

def main():
    try:
        print("Starting Email Assistant")
        
        # Check requirements first
        check_requirements()
        
        # Initialize configuration
        config_manager = ConfigManager()
        if not config_manager.config['openai_api_key'] or not config_manager.config['assistants']:
            print("First time setup required")
            show_first_time_setup()
            
            # Reload configuration after setup
            config_manager = ConfigManager()
            if not config_manager.config['openai_api_key'] or not config_manager.config['assistants']:
                print("Setup incomplete, exiting")
                return
        
        # Create main application
        print("Initializing application")
        assistant = EmailAssistant()
        
        # Create and display main window
        print("Creating main window")
        root = assistant.create_gui()
        
        # Center the window
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')
        
        print("Starting main loop")
        root.mainloop()
        
    except ImportError as e:
        print(f"Missing requirements: {str(e)}")
        messagebox.showerror("Missing Requirements", str(e))
    except Exception as e:
        print(f"Error in main function: {str(e)}")
        messagebox.showerror(
            "Fatal Error",
            f"Application failed to start:\n\n{str(e)}\n\nPlease check the logs for more information."
        )

if __name__ == "__main__":
    main()
