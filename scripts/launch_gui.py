#!/usr/bin/env python3
"""
Launcher script for Project Revelare Archive Explorer GUI
"""

import sys
import os
import subprocess

def check_dependencies():
    """Check if required dependencies are installed."""
    try:
        import tkinter
        print("[OK] Tkinter available")
    except ImportError:
        print("[ERROR] Tkinter not available. Please install Python with Tkinter support.")
        return False
    
    try:
        from PIL import Image, ImageTk
        print("[OK] Pillow (PIL) available")
    except ImportError:
        print("[WARNING] Pillow not installed. Installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
            print("[OK] Pillow installed successfully")
        except subprocess.CalledProcessError:
            print("[ERROR] Failed to install Pillow. Please install manually: pip install Pillow")
            return False
    
    return True

def main():
    """Main launcher function."""
    print("Project Revelare - Archive Explorer GUI")
    print("=" * 40)
    
    # Check dependencies
    if not check_dependencies():
        print("\n[ERROR] Dependency check failed. Please install required packages.")
        input("Press Enter to exit...")
        return 1
    
    print("\n[OK] All dependencies available")
    print("[INFO] Starting Archive Explorer GUI...")
    
    # Launch the GUI
    try:
        # Try to import from demos directory first
        import sys
        import os
        from pathlib import Path
        
        # Add demos directory to path
        demos_path = Path(__file__).parent.parent / "demos"
        sys.path.insert(0, str(demos_path))
        
        try:
            from archive_explorer_gui import main as gui_main  # type: ignore
            gui_main()
        except ImportError:
            # Fallback: Create a simple file browser GUI
            print("[INFO] Archive Explorer GUI not found, launching simple file browser...")
            from tkinter import Tk, filedialog, messagebox
            import subprocess
            import webbrowser
            
            def simple_file_browser():
                root = Tk()
                root.withdraw()  # Hide the main window
                
                # Ask user what they want to do
                choice = messagebox.askyesnocancel(
                    "Project Revelare - File Explorer",
                    "Choose an option:\n\nYes = Open file browser\nNo = Open web interface\nCancel = Exit"
                )
                
                if choice is True:
                    # Open file browser
                    file_path = filedialog.askopenfilename(
                        title="Select file to analyze",
                        filetypes=[
                            ("All supported", "*.zip;*.pdf;*.docx;*.xlsx;*.txt;*.json;*.csv"),
                            ("Archives", "*.zip;*.rar;*.7z"),
                            ("Documents", "*.pdf;*.docx;*.xlsx"),
                            ("Data files", "*.txt;*.json;*.csv"),
                            ("All files", "*.*")
                        ]
                    )
                    if file_path:
                        # Launch CLI processing
                        subprocess.run([
                            sys.executable, "-m", "revelare_core", "cli", 
                            "-p", "gui_analysis", "-f", file_path
                        ])
                elif choice is False:
                    # Open web interface
                    webbrowser.open("http://localhost:5000")
                    subprocess.run([sys.executable, "-m", "revelare_core", "web"])
                
                root.destroy()
            
            simple_file_browser()
            
    except Exception as e:
        print(f"[ERROR] Error starting GUI: {e}")
        print("[INFO] Try using the web interface instead: python run_revelare.py web")
        input("Press Enter to exit...")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
