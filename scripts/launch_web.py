#!/usr/bin/env python3
"""
Web Interface Launcher for Project Revelare
Starts the Flask web application with proper configuration
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Launch the Project Revelare web interface"""
    print("Project Revelare - Web Interface Launcher")
    print("=" * 40)
    
    try:
        # Import and start the Flask app
        from suite import app, init_database, logger, Config
        
        # Initialize database
        if not init_database():
            print("[ERROR] Failed to initialize database. Please check your configuration.")
            return 1
        
        print(f"[OK] Database initialized successfully")
        print(f"[OK] Starting web server on {Config.HOST}:{Config.PORT}")
        print(f"[INFO] Open your browser to: http://{Config.HOST}:{Config.PORT}")
        print(f"[INFO] Press Ctrl+C to stop the server")
        print("-" * 40)
        
        # Start the Flask app
        app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
        
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user")
        return 0
    except Exception as e:
        print(f"[ERROR] Failed to start web interface: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
