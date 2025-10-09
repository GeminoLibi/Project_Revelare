#!/usr/bin/env python3
"""
Minimal test of the Archive Explorer GUI
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os

class MinimalArchiveExplorer:
    def __init__(self, root):
        self.root = root
        self.root.title("Project Revelare - Archive Explorer (Test)")
        self.root.geometry("800x600")
        
        # State variables
        self.current_directory = None
        self.status_var = None
        
        # Create GUI
        self.create_widgets()
        self.setup_layout()
    
    def create_widgets(self):
        """Create all GUI widgets."""
        # Main menu
        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)
        
        # File menu
        self.file_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open Directory", command=self.open_directory)
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Main frame
        self.main_frame = ttk.Frame(self.root)
        
        # Left panel - File tree
        self.left_frame = ttk.LabelFrame(self.main_frame, text="Directory Contents", padding=10)
        self.tree_frame = ttk.Frame(self.left_frame)
        
        # Treeview with scrollbar
        self.tree = ttk.Treeview(self.tree_frame, show="tree")
        self.tree_scroll = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.tree_scroll.set)
        
        # Right panel - Preview
        self.right_frame = ttk.LabelFrame(self.main_frame, text="Preview", padding=10)
        
        # Preview area
        self.preview_frame = ttk.Frame(self.right_frame)
        self.preview_text = scrolledtext.ScrolledText(self.preview_frame, wrap=tk.WORD, height=20)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        
        # Bind events
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
    
    def setup_layout(self):
        """Setup the layout of widgets."""
        # Main frame
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self.tree_frame.pack(fill=tk.BOTH, expand=True)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right panel
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Preview area
        self.preview_frame.pack(fill=tk.BOTH, expand=True)
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def open_directory(self):
        """Open a normal directory."""
        dir_path = filedialog.askdirectory(title="Select Directory")
        
        if dir_path:
            self.load_directory(dir_path)
    
    def load_directory(self, directory_path: str):
        """Load and display directory contents."""
        self.current_directory = directory_path
        self.status_var.set(f"Loading directory: {os.path.basename(directory_path)}")
        
        try:
            # Clear existing tree
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Build directory tree
            self.build_directory_tree(directory_path)
            
            self.status_var.set(f"Loaded: {os.path.basename(directory_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load directory: {str(e)}")
            self.status_var.set("Error loading directory")
    
    def build_directory_tree(self, root_path: str):
        """Build the file tree from directory structure."""
        def add_directory_items(parent, path):
            try:
                items = os.listdir(path)
                items.sort(key=lambda x: (os.path.isdir(os.path.join(path, x)), x.lower()))
                
                for item in items:
                    item_path = os.path.join(path, item)
                    item_id = self.tree.insert(parent, "end", text=item, open=False)
                    
                    if os.path.isdir(item_path):
                        add_directory_items(item_id, item_path)
            except PermissionError:
                pass
        
        # Add root directory
        root_name = os.path.basename(root_path) or root_path
        root_id = self.tree.insert("", "end", text=root_name, open=True)
        add_directory_items(root_id, root_path)
    
    def on_tree_select(self, event):
        """Handle tree selection."""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            file_path = self.get_file_path(item)
            if file_path and os.path.isfile(file_path):
                self.preview_file(file_path)
    
    def get_file_path(self, item) -> str:
        """Get the full file path for a tree item."""
        if not self.current_directory:
            return None
        
        # Build path from tree item
        path_parts = []
        current = item
        
        while current:
            text = self.tree.item(current, "text")
            path_parts.insert(0, text)
            current = self.tree.parent(current)
        
        if not path_parts:
            return None
        
        return os.path.join(self.current_directory, *path_parts)
    
    def preview_file(self, file_path: str):
        """Preview a file in the preview area."""
        if not file_path or not os.path.isfile(file_path):
            return
        
        # Clear previous preview
        self.preview_text.delete(1.0, tk.END)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Limit preview length
            if len(content) > 5000:
                content = content[:5000] + "\n\n[Content truncated...]"
            
            self.preview_text.insert(tk.END, content)
            
        except Exception as e:
            self.preview_text.insert(tk.END, f"Error reading file: {str(e)}")

def main():
    """Main function."""
    root = tk.Tk()
    app = MinimalArchiveExplorer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
