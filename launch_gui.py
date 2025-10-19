import sys
import os
import subprocess
from pathlib import Path
from tkinter import Tk, filedialog, messagebox
import webbrowser

# Add the project root directory to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def check_dependencies():
    try:
        import tkinter
    except ImportError:
        messagebox.showerror("Dependency Error", "Tkinter not found. Please install python3-tk or a similar package.")
        return False
    return True

def main():
    if not check_dependencies():
        return 1
    
    try:
        root = Tk()
        root.withdraw()
        
        choice = messagebox.askyesnocancel(
            "Project Revelare Launcher",
            "Choose an option:\n\n[Yes] = Launch Web Interface\n[No] = Exit"
        )
        
        if choice is True:
            # This would point to the launch_web.py script
            web_launcher_path = Path(__file__).resolve().parent / "launch_web.py"
            if web_launcher_path.exists():
                subprocess.Popen([sys.executable, str(web_launcher_path)])
            else:
                messagebox.showerror("Error", "launch_web.py not found. Cannot start the web interface.")
        
        root.destroy()
            
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())