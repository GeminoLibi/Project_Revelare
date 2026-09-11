"""
Project Revelare - Executable Launcher
This script is optimized for PyInstaller packaging
"""
import sys
import os
import webbrowser
import time
import threading
from pathlib import Path

# Add the project root directory to Python path
# When running as exe, sys.executable points to the exe location
if getattr(sys, 'frozen', False):
    # Running as compiled exe
    application_path = os.path.dirname(sys.executable)
else:
    # Running as script
    application_path = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, application_path)

def open_browser_delayed(url, delay=2.0):
    """Open browser after a delay to allow server to start"""
    def delayed_open():
        time.sleep(delay)
        try:
            webbrowser.open(url)
            print(f"Opened browser to: {url}")
        except Exception as e:
            print(f"Could not open browser: {e}")
    
    thread = threading.Thread(target=delayed_open, daemon=True)
    thread.start()

def main():
    print("=" * 50)
    print("  Project Revelare - Digital Forensics Platform")
    print("=" * 50)
    print("\nStarting web interface...")
    print("The browser will open automatically when ready.\n")
    
    try:
        from revelare.cli.suite import launch_web_app
        
        # Launch the web app (this will start the Flask server)
        # The launch_web_app function handles port finding and browser opening
        launch_web_app()
        
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user.")
        return 0
    except Exception as e:
        print(f"[ERROR] Failed to start web interface: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")
        return 1

if __name__ == "__main__":
    sys.exit(main())
