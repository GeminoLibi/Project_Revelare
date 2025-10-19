import sys
import os
from pathlib import Path

# Add the project root directory to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def main():
    print("Project Revelare - Web Interface Launcher")
    print("=" * 40)
    
    try:
        from revelare.cli.suite import launch_web_app
        launch_web_app()
        
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user.")
        return 0
    except Exception as e:
        print(f"[ERROR] Failed to start web interface: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())