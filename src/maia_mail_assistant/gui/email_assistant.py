import tkinter as tk
from tkinter import ttk, messagebox
import openai
import time
import json
import webbrowser
import threading
import tkinterweb
from typing import Dict, List, Optional

from ..config import ConfigManager
from ..models import AccountManager
from .config_windows import ConfigWindow, AccountConfigWindow
from .widgets import EmailFormatter

class EmailAssistant:
    def __init__(self):
        print("Initializing EmailAssistant")
        self.config_manager = ConfigManager()
        self.account_manager = AccountManager()
        self.openai_api_key = self.config_manager.config['openai_api_key']
        self.assistants = self.config_manager.config.get('assistants', {})
        self.current_assistant = next(iter(self.assistants.keys())) if self.assistants else None
        self.current_account = None
        
        # State management
        self.emails = []
        self.selected_emails = []
        self.draft_responses = {}
        self.threads = {}
        
        if self.openai_api_key:
            openai.api_key = self.openai_api_key
        
        print("EmailAssistant initialized")

    def create_gui(self):
        self.root = tk.Tk()
        self.root.title("Email Assistant")
        self.root.geometry("1200x800")
        
        # Create menu
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(
            label="Configure API Keys",
            command=lambda: ConfigWindow(
                self.root, 
                self.config_manager,
                self.update_credentials
            )
        )
        settings_menu.add_command(
            label="Manage Email Accounts",
            command=lambda: AccountConfigWindow(
                self.root,
                self.account_manager,
                self.refresh_account_selector
            )
        )
        
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Top frame for selectors
        top_frame = ttk.Frame(main_container)
        top_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Account selector frame
        account_frame = ttk.Frame(top_frame)
        account_frame.pack(fill=tk.X)
        
        ttk.Label(account_frame, text="Email Account:").pack(side=tk.LEFT, padx=5)
        self.account_selector = ttk.Combobox(
            account_frame,
            values=list(self.account_manager.accounts.keys()),
            state="readonly",
            width=30
        )
        self.account_selector.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(account_frame, text="Assistant:").pack(side=tk.LEFT, padx=5)
        self.assistant_selector = ttk.Combobox(
            account_frame,
            values=list(self.assistants.keys()),
            state="readonly",
            width=30
        )
        self.assistant_selector.pack(side=tk.LEFT, padx=5)
        
        # Initialize selectors
        if self.account_manager.accounts:
            self.account_selector.set(next(iter(self.account_manager.accounts.keys())))
            self.account_selector.bind('<<ComboboxSelected>>', self.on_account_selected)
            self.current_account = self.account_manager.get_account(self.account_selector.get())
        
        if self.assistants:
            self.assistant_selector.set(self.current_assistant)
            self.assistant_selector.bind(
                '<<ComboboxSelected>>',
                lambda e: setattr(self, 'current_assistant', self.assistant_selector.get())
            )
        
        # Email list frame
        list_frame = ttk.Frame(main_container)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Fetch emails button
        ttk.Button(
            list_frame,
            text="Fetch Emails",
            command=lambda: self.refresh_email_list()
        ).pack(pady=5)
        
        # Create email list
        self.email_listbox = ttk.Treeview(
            list_frame,
            columns=("From", "Subject", "Date", "Preview"),
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        self.email_listbox.heading("From", text="From")
        self.email_listbox.heading("Subject", text="Subject")
        self.email_listbox.heading("Date", text="Date")
        self.email_listbox.heading("Preview", text="Preview")
        
        self.email_listbox.column("From", width=200)
        self.email_listbox.column("Subject", width=300)
        self.email_listbox.column("Date", width=150)
        self.email_listbox.column("Preview", width=400)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            list_frame,
            orient="vertical",
            command=self.email_listbox.yview
        )
        self.email_listbox.configure(yscrollcommand=scrollbar.set)
        
        # Pack list and scrollbar
        self.email_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bottom buttons
        button_frame = ttk.Frame(main_container)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            button_frame,
            text="Generate Responses",
            command=self.handle_response_generation
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Preview Full Body",
            command=self.show_full_body_preview
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Review & Send",
            command=lambda: self.show_review_window()
        ).pack(side=tk.LEFT, padx=5)
        
        return self.root

    def refresh_email_list(self):
        try:
            if not self.current_account:
                messagebox.showerror("Error", "No email account selected!")
                return
            
            # Clear existing items
            for item in self.email_listbox.get_children():
                self.email_listbox.delete(item)
            
            # Fetch new emails
            self.emails = self.current_account.provider.get_emails()
            
            for email in self.emails:
                preview_lines = email['body'].split('\n')[:2]
                preview = '\n'.join(preview_lines)
                if len(email['body']) > len(preview):
                    preview += '...'
                
                self.email_listbox.insert("", "end", values=(
                    email['sender'],
                    email['subject'],
                    email['timestamp'],
                    preview
                ), tags=(email['id'],))
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch emails: {str(e)}")

    def show_full_body_preview(self):
        """Show window for full email body preview with HTML support"""
        selected_items = self.email_listbox.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "Please select at least one email!")
            return
        
        preview_window = tk.Toplevel(self.root)
        preview_window.title("Full Email Preview")
        preview_window.geometry("800x600")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(preview_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        for item in selected_items:
            email_id = self.email_listbox.item(item)["tags"][0]
            email_data = next((e for e in self.emails if str(e['id']) == str(email_id)), None)
            
            if email_data:
                frame = ttk.Frame(notebook)
                notebook.add(frame, text=f"Email: {email_data['subject'][:30]}...")
                
                # Create inner notebook for different views
                inner_notebook = ttk.Notebook(frame)
                inner_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
                # HTML Preview tab
                html_frame = ttk.Frame(inner_notebook)
                inner_notebook.add(html_frame, text="HTML View")
                
                preview_html = tkinterweb.HtmlFrame(html_frame, messages_enabled=False)
                preview_html.pack(fill=tk.BOTH, expand=True)
                
                # Create HTML content
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            color: #333333;
                            max-width: 800px;
                            margin: 0 auto;
                            padding: 10px;
                            font-size:13px;
                        }}
                        .header {{
                            background-color: #f8f9fa;
                            border-bottom: 1px solid #e9ecef;
                            padding: 10px;
                            margin-bottom: 20px;
                        }}
                        .header-field {{
                            margin: 5px 0;
                        }}
                        .header-label {{
                            font-weight: bold;
                            color: #495057;
                            width: 70px;
                            display: inline-block;
                        }}
                        .email-body {{
                            padding: 10px;
                            background: white;
                        }}
                        pre {{
                            white-space: pre-wrap;
                            word-wrap: break-word;
                            padding: 10px;
                            background: #f8f9fa;
                            border: 1px solid #e9ecef;
                        }}
                    </style>
                </head>
                <body>
                    <div class="header">
                        <div class="header-field">
                            <span class="header-label">From:</span> {email_data['sender']}
                        </div>
                        <div class="header-field">
                            <span class="header-label">Subject:</span> {email_data['subject']}
                        </div>
                        <div class="header-field">
                            <span class="header-label">Date:</span> {email_data['timestamp']}
                        </div>
                    </div>
                    <div class="email-body">
                        {self._format_email_body(email_data['body'])}
                    </div>
                </body>
                </html>
                """
                preview_html.load_html(html_content)
                
                # Plain Text tab
                text_frame = ttk.Frame(inner_notebook)
                inner_notebook.add(text_frame, text="Plain Text")
                
                # Create text widget with scrollbar
                text_container = ttk.Frame(text_frame)
                text_container.pack(fill=tk.BOTH, expand=True)
                
                text_widget = tk.Text(text_container, wrap=tk.WORD)
                scrollbar = ttk.Scrollbar(text_container, orient="vertical", 
                                        command=text_widget.yview)
                text_widget.configure(yscrollcommand=scrollbar.set)
                
                # Configure tags for formatting
                text_widget.tag_configure("header", font=("Arial", 10, "bold"))
                text_widget.tag_configure("body", font=("Arial", 10))
                
                # Insert content with formatting
                text_widget.insert(tk.END, "From: ", "header")
                text_widget.insert(tk.END, f"{email_data['sender']}\n\n", "body")
                
                text_widget.insert(tk.END, "Subject: ", "header")
                text_widget.insert(tk.END, f"{email_data['subject']}\n\n", "body")
                
                text_widget.insert(tk.END, "Date: ", "header")
                text_widget.insert(tk.END, f"{email_data['timestamp']}\n\n", "body")
                
                text_widget.insert(tk.END, "Body:\n\n", "header")
                text_widget.insert(tk.END, str(email_data['body']), "body")
                
                text_widget.config(state=tk.DISABLED)
                
                # Pack text view widgets
                text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
               

    def _format_email_body(self, body: str) -> str:
        """Format email body for HTML display"""
        try:
            # Check if body is already HTML
            if body.strip().lower().startswith('<!doctype html') or '<html' in body.lower():
                return body
            
            # Check if body is plain text that contains HTML tags
            if '<' in body and '>' in body and ('<p' in body.lower() or '<div' in body.lower() or '<br' in body.lower()):
                return body
            
            # Convert plain text to HTML with proper formatting
            formatted_body = body.replace('\n', '<br>')
            # Detect and preserve URLs
            url_pattern = r'(https?://\S+)'
            formatted_body = re.sub(url_pattern, r'<a href="\1">\1</a>', formatted_body)
            
            return formatted_body
        except Exception as e:
            print(f"Error formatting email body: {e}")
            return body        

    def handle_response_generation(self):
        """Handle generating responses for selected emails"""
        try:
            selected_items = self.email_listbox.selection()
            if not selected_items:
                messagebox.showwarning("Warning", "Please select at least one email!")
                return

            if not self.current_assistant:
                messagebox.showerror("Error", "No assistant selected!")
                return

            assistant_id = self.assistants.get(self.current_assistant)
            if not assistant_id:
                messagebox.showerror("Error", f"No ID found for assistant: {self.current_assistant}")
                return

            # Clear previous selections and responses
            self.selected_emails = []
            self.draft_responses = {}

            success_count = 0
            for item in selected_items:
                try:
                    # Get the values directly from the treeview item
                    item_values = self.email_listbox.item(item)
                    email_id = item_values["tags"][0]
                    
                    # Find the corresponding email in self.emails
                    email_data = None
                    for email in self.emails:
                        # Convert both IDs to strings for comparison
                        if str(email.get('id', '')).strip() == str(email_id).strip():
                            email_data = email
                            break

                    if email_data:
                        print(f"Processing email: {email_data.get('subject', 'No subject')}")
                        self.selected_emails.append(email_data)
                        response = self.generate_response(email_data)
                        if response:
                            self.draft_responses[str(email_id)] = response
                            success_count += 1
                    else:
                        print(f"Could not find email data for ID: {email_id}")
                except Exception as e:
                    print(f"Error processing email {email_id}: {str(e)}")
                    continue

            if success_count > 0:
                messagebox.showinfo("Success", f"Generated {success_count} responses!")
                self.show_review_window()
            else:
                messagebox.showerror("Error", "Failed to generate any responses")

        except Exception as e:
            print(f"Error in handle_response_generation: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate responses: {str(e)}")

    def generate_response(self, email_data: Dict) -> str:
        """Generate email response using OpenAI assistant"""
        try:
            if not self.openai_api_key or not self.assistants:
                raise ValueError("OpenAI API Key and Assistant must be configured!")
    
            # Ensure all fields are properly decoded strings
            sender = str(email_data.get('sender', '')).strip()
            subject = str(email_data.get('subject', '')).strip()
            body = str(email_data.get('body', '')).strip()
    
            thread_id = self.threads.get(email_data['id'])
            if not thread_id:
                thread = openai.beta.threads.create()
                thread_id = thread.id
                self.threads[email_data['id']] = thread_id
    
            # Create a clear, structured prompt
            prompt = (
                f"Please draft a professional email response to this email. "
                f"Use proper markdown formatting for better readability:\n\n"
                f"Original Email Details:\n"
                f"From: {sender}\n"
                f"Subject: {subject}\n"
                f"Body:\n{body}\n\n"
                f"Requirements:\n"
                f"1. Use proper markdown formatting\n"
                f"2. Include appropriate greeting and closing\n"
                f"3. Address all points from the original email\n"
                f"4. Keep a professional tone\n"
                f"5. Use proper spacing and paragraphs\n"
                f"6. If the original email is in a different language, respond in the same language"
            )
    
            print(f"Generating response for email: {subject}")
            print(f"Using assistant: {self.current_assistant}")
    
            # Create message in thread
            message = openai.beta.threads.messages.create(
                thread_id=thread_id,
                role="user",
                content=prompt
            )
    
            # Run the assistant
            run = openai.beta.threads.runs.create(
                thread_id=thread_id,
                assistant_id=self.assistants[self.current_assistant]
            )
    
            # Wait for completion with timeout
            start_time = time.time()
            timeout = 60  # 60 seconds timeout
            while True:
                if time.time() - start_time > timeout:
                    raise Exception("Response generation timed out")
    
                run_status = openai.beta.threads.runs.retrieve(
                    thread_id=thread_id,
                    run_id=run.id
                )
    
                if run_status.status == 'completed':
                    break
                elif run_status.status == 'failed':
                    raise Exception(f"Assistant failed: {run_status.last_error}")
                elif run_status.status == 'expired':
                    raise Exception("Response generation expired")
    
                time.sleep(1)
    
            # Get response
            messages = openai.beta.threads.messages.list(thread_id=thread_id)
            for message in messages.data:
                if message.role == "assistant":
                    return message.content[0].text.value
    
            raise Exception("No response generated")
    
        except Exception as e:
            print(f"Error generating response: {str(e)}")
            raise

    def generate_response_with_instructions(self, email_data: Dict, current_response: str, instructions: str) -> str:
        """Generate a new response based on the current response and additional instructions"""
        try:
            if not self.openai_api_key or not self.assistants:
                raise ValueError("OpenAI API Key and Assistant must be configured!")
            
            thread_id = self.threads.get(email_data['id'])
            if not thread_id:
                thread = openai.beta.threads.create()
                thread_id = thread.id
                self.threads[email_data['id']] = thread_id
            
            prompt = (
                f"Please revise the following email response according to these instructions:\n\n"
                f"Instructions: {instructions}\n\n"
                f"Original Email:\n"
                f"From: {email_data['sender']}\n"
                f"Subject: {email_data['subject']}\n"
                f"Body:\n{email_data['body']}\n\n"
                f"Current Response:\n{current_response}\n\n"
                f"Requirements:\n"
                f"1. Keep the professional tone\n"
                f"2. Maintain proper formatting (markdown)\n"
                f"3. Address the new instructions while keeping relevant parts of the current response\n"
                f"4. Include appropriate greeting and closing\n"
                f"5. Ensure proper spacing and paragraphs"
            )
            
            # Create message in thread
            openai.beta.threads.messages.create(
                thread_id=thread_id,
                role="user",
                content=prompt
            )
            
            # Run the assistant
            run = openai.beta.threads.runs.create(
                thread_id=thread_id,
                assistant_id=self.assistants[self.current_assistant]
            )
            
            # Wait for completion
            start_time = time.time()
            timeout = 60  # 60 seconds timeout
            
            while True:
                if time.time() - start_time > timeout:
                    raise Exception("Response generation timed out")
                
                run_status = openai.beta.threads.runs.retrieve(
                    thread_id=thread_id,
                    run_id=run.id
                )
                
                if run_status.status == 'completed':
                    break
                elif run_status.status == 'failed':
                    raise Exception(f"Assistant failed: {run_status.last_error}")
                elif run_status.status == 'expired':
                    raise Exception("Response generation expired")
                
                time.sleep(1)
            
            # Get response
            messages = openai.beta.threads.messages.list(thread_id=thread_id)
            for message in messages.data:
                if message.role == "assistant":
                    return message.content[0].text.value
            
            raise Exception("No response generated")
            
        except Exception as e:
            print(f"Error generating response with instructions: {str(e)}")
            raise Exception(f"Failed to generate response: {str(e)}")

    def show_review_window(self):
        """Show window for reviewing responses"""
        if not self.draft_responses:
            messagebox.showwarning("Warning", "No responses to review! Please generate responses first.")
            return

        review_window = tk.Toplevel(self.root)
        review_window.title("Review Responses")
        review_window.geometry("1200x800")

        # Main container
        main_container = ttk.Frame(review_window)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Create canvas for scrolling
        canvas = tk.Canvas(main_container)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        # Configure scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas_frame = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        
        def configure_canvas(event):
            canvas.itemconfig(canvas_frame, width=event.width)
        canvas.bind('<Configure>', configure_canvas)

        # Add responses to scrollable frame
        for email_id, response in self.draft_responses.items():
            try:
                # Find the corresponding email in selected_emails
                email_data = None
                for email in self.selected_emails:
                    if str(email.get('id', '')).strip() == str(email_id).strip():
                        email_data = email
                        break

                if email_data:
                    # Create frame for this response
                    response_frame = ttk.LabelFrame(scrollable_frame, 
                                                 text=f"Response to: {email_data['subject']}")
                    response_frame.pack(fill=tk.X, padx=5, pady=5)

                    # Headers section
                    headers_frame = ttk.Frame(response_frame)
                    headers_frame.pack(fill=tk.X, padx=5, pady=5)

                    # Add fields (To, CC, Subject)
                    ttk.Label(headers_frame, text="To:").grid(row=0, column=0, sticky="w")
                    to_entry = ttk.Entry(headers_frame, width=50)
                    to_entry.insert(0, email_data['sender'])
                    to_entry.grid(row=0, column=1, sticky="ew", padx=5)

                    ttk.Label(headers_frame, text="CC:").grid(row=1, column=0, sticky="w")
                    cc_entry = ttk.Entry(headers_frame, width=50)
                    cc_entry.grid(row=1, column=1, sticky="ew", padx=5)

                    ttk.Label(headers_frame, text="Subject:").grid(row=2, column=0, sticky="w")
                    subject_entry = ttk.Entry(headers_frame, width=50)
                    subject_entry.insert(0, f"Re: {email_data['subject']}")
                    subject_entry.grid(row=2, column=1, sticky="ew", padx=5)

                    # Create notebook for edit/preview tabs
                    notebook = ttk.Notebook(response_frame)
                    notebook.pack(fill=tk.BOTH, padx=5, pady=5)

                    # Edit tab
                    edit_frame = ttk.Frame(notebook)
                    notebook.add(edit_frame, text="Edit Response")
                    
                    edit_text = tk.Text(edit_frame, wrap=tk.WORD, height=15, font=("Courier", 12))
                    edit_scroll = ttk.Scrollbar(edit_frame, orient="vertical", 
                                              command=edit_text.yview)
                    edit_text.configure(yscrollcommand=edit_scroll.set)
                    
                    edit_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                    edit_scroll.pack(side=tk.RIGHT, fill=tk.Y)
                    edit_text.insert("1.0", response)

                    # Preview tab
                    preview_frame = ttk.Frame(notebook)
                    notebook.add(preview_frame, text="Preview")
                    
                    preview_html = tkinterweb.HtmlFrame(preview_frame, messages_enabled=False)
                    preview_html.pack(fill=tk.BOTH, expand=True)
                    
                    def update_preview(event=None, text_widget=edit_text, html_widget=preview_html):
                        content = text_widget.get("1.0", tk.END)
                        html_content = EmailFormatter.markdown_to_html(content)
                        html_widget.load_html(html_content)
                    
                    edit_text.bind('<KeyRelease>', update_preview)
                    update_preview()

                    # Buttons
                    button_frame = ttk.Frame(response_frame)
                    button_frame.pack(fill=tk.X, padx=5, pady=5)
                    
                    ttk.Button(button_frame, text="Regenerate",
                              command=lambda e=email_data, t=edit_text: 
                              self.regenerate_response(e, t)).pack(side=tk.LEFT, padx=5)
                    
                    ttk.Button(button_frame, text="Send",
                              command=lambda e=email_data, t=edit_text, to=to_entry, 
                                             c=cc_entry, s=subject_entry:
                              self.confirm_and_send(e, t.get("1.0", tk.END),
                                                to.get(), c.get(), s.get())).pack(side=tk.LEFT, padx=5)
                else:
                    print(f"Could not find email data for ID: {email_id}")

            except Exception as e:
                print(f"Error creating review frame: {str(e)}")
                continue

        # Pack canvas and scrollbar
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.configure(yscrollcommand=scrollbar.set)

    def regenerate_response(self, email_data: Dict, response_text: tk.Text):
        """Regenerate a response with additional instructions"""
        try:
            dialog = tk.Toplevel(self.root)
            dialog.title("Regenerate Response")
            dialog.geometry("400x200")
            
            ttk.Label(dialog, text="Enter additional instructions:").pack(pady=10)
            instruction_text = tk.Text(dialog, height=4)
            instruction_text.pack(pady=10, padx=10)
            
            def submit():
                instructions = instruction_text.get("1.0", tk.END).strip()
                dialog.destroy()
                
                if instructions:
                    try:
                        new_response = self.generate_response_with_instructions(
                            email_data, 
                            response_text.get("1.0", tk.END),
                            instructions
                        )
                        if new_response:
                            # Get the parent notebook and preview frame
                            notebook = response_text.master.master
                            preview_frame = notebook.winfo_children()[1]  # Second tab
                            preview_html = preview_frame.winfo_children()[0]  # HtmlFrame
                            
                            # Update text content
                            response_text.delete("1.0", tk.END)
                            response_text.insert("1.0", new_response)
                            
                            # Update HTML preview
                            html_content = EmailFormatter.markdown_to_html(new_response)
                            preview_html.load_html(html_content)
                            
                            # Update stored response
                            self.draft_responses[email_data['id']] = new_response
                            
                            messagebox.showinfo("Success", "Response regenerated successfully!")
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to regenerate response: {str(e)}")
            
            ttk.Button(dialog, text="Submit", command=submit).pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open regeneration dialog: {str(e)}")

    def confirm_and_send(self, email_data: Dict, response: str, to: str, cc: str, subject: str):
        """Confirm and send email response"""
        if messagebox.askyesno("Confirm", "Are you sure you want to send this response?"):
            try:
                # Add signature if configured
                if self.current_account and self.current_account.signature:
                    response = f"{response}\n\n{self.current_account.signature}"
                
                self.current_account.provider.send_email(to, subject, response, cc)
                messagebox.showinfo("Success", "Email sent successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send email: {str(e)}")

    def refresh_account_selector(self):
        """Update the account selector with current accounts"""
        current_accounts = list(self.account_manager.accounts.keys())
        self.account_selector['values'] = current_accounts
        
        if current_accounts and not self.account_selector.get():
            self.account_selector.set(current_accounts[0])
            self.current_account = self.account_manager.get_account(current_accounts[0])

    def on_account_selected(self, event):
        """Handle account selection change"""
        email = self.account_selector.get()
        self.current_account = self.account_manager.get_account(email)
        # Clear the email list
        for item in self.email_listbox.get_children():
            self.email_listbox.delete(item)

    def update_credentials(self, api_key: str, assistants: Dict[str, str]):
        """Update OpenAI credentials and refresh the UI"""
        self.openai_api_key = api_key
        self.assistants = assistants
        openai.api_key = api_key
        
        # Update assistant selector
        self.assistant_selector['values'] = list(self.assistants.keys())
        if self.assistants:
            self.current_assistant = next(iter(self.assistants.keys()))
            self.assistant_selector.set(self.current_assistant)
        
        messagebox.showinfo("Success", "Credentials updated successfully!")     
