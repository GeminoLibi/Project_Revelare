#!/usr/bin/env python3
"""
Simple test to verify GUI is working
"""

import tkinter as tk
from tkinter import ttk

def test_basic_gui():
    """Test basic tkinter functionality."""
    root = tk.Tk()
    root.title("GUI Test")
    root.geometry("400x300")
    
    # Add a simple label
    label = ttk.Label(root, text="GUI Test - If you can see this, tkinter is working!")
    label.pack(pady=20)
    
    # Add a button
    button = ttk.Button(root, text="Test Button", command=lambda: print("Button clicked!"))
    button.pack(pady=10)
    
    # Add a text widget
    text = tk.Text(root, height=10, width=50)
    text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
    text.insert(tk.END, "This is a test text widget.\nIf you can see this, the GUI is working properly.")
    
    print("GUI test window should be visible now.")
    root.mainloop()

if __name__ == "__main__":
    test_basic_gui()
