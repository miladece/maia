import tkinter as tk
from tkinter import ttk
import markdown
from bs4 import BeautifulSoup

class HTMLPreviewWidget(tk.Text):
    """Custom widget for HTML-like email preview with proper formatting and scrolling"""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            wrap=tk.WORD,
            padx=20,
            pady=20,
            font=("Arial", 12),
            cursor="arrow",
            spacing1=8,  # Space between lines
            spacing2=2,  # Space between paragraphs
            spacing3=0,  # Space after paragraphs
        )
        
        # Configure tags for different elements
        self.tag_configure("h1", font=("Arial", 16, "bold"), spacing1=16, spacing3=8)
        self.tag_configure("h2", font=("Arial", 14, "bold"), spacing1=14, spacing3=6)
        self.tag_configure("normal", font=("Arial", 12))
        self.tag_configure("bold", font=("Arial", 12, "bold"))
        self.tag_configure("italic", font=("Arial", 12, "italic"))
        self.tag_configure("list_item", lmargin1=40, lmargin2=40)
        self.tag_configure("quote", lmargin1=30, lmargin2=30, font=("Arial", 12, "italic"))
        self.tag_configure("signature", font=("Arial", 11), foreground="#666666")
        
        # Bind mouse wheel for scrolling
        self.bind("<MouseWheel>", self._on_mousewheel)
        self.bind("<Button-4>", self._on_mousewheel)
        self.bind("<Button-5>", self._on_mousewheel)
    
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling events."""
        if event.num == 4:
            self.yview_scroll(-1, "units")
        elif event.num == 5:
            self.yview_scroll(1, "units")
        else:
            self.yview_scroll(int(-1 * (event.delta / 120)), "units")

class EmailFormatter:
    """Handles email formatting and conversion between formats."""
    
    @staticmethod
    def markdown_to_html(text: str) -> str:
        """Convert markdown to properly formatted HTML."""
        html_content = markdown.markdown(
            text,
            extensions=['extra', 'nl2br', 'sane_lists']
        )
        
        template = f"""
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
                    padding: 20px;
                }}
                p {{
                    margin: 0 0 1em 0;
                    font-size: 14px;
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                    margin-top: 1em;
                    margin-bottom: 0.5em;
                }}
                ul, ol {{
                    margin: 1em 0;
                    padding-left: 2em;
                }}
                li {{
                    margin: 0.5em 0;
                    font-size: 14px;
                }}
                blockquote {{
                    border-left: 4px solid #e0e0e0;
                    margin: 1em 0;
                    padding-left: 1em;
                    color: #666;
                }}
                .signature {{
                    margin-top: 2em;
                    padding-top: 1em;
                    border-top: 1px solid #e0e0e0;
                    color: #666;
                    font-size: 12px;
                }}
                .email-content {{
                    background-color: white;
                    padding: 20px;
                    border-radius: 4px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }}
            </style>
        </head>
        <body>
            <div class="email-content">
                {html_content}
            </div>
        </body>
        </html>
        """
        return template
