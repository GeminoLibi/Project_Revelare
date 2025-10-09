#!/usr/bin/env python3
"""
Shutdown script for Project Revelare server
"""

import os
import sys
import signal
import subprocess
import time

def shutdown_server():
    """Shutdown the Project Revelare server"""
    print("Shutting down Project Revelare server...")
    
    # Find and kill Python processes running suite.py
    try:
        # Get list of Python processes
        result = subprocess.run(['tasklist', '/fi', 'imagename eq python3.13.exe'], 
                              capture_output=True, text=True, shell=True)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'python3.13.exe' in line and 'suite.py' in line:
                    # Extract PID
                    parts = line.split()
                    if len(parts) >= 2:
                        pid = parts[1]
                        print(f"Terminating process {pid}...")
                        subprocess.run(['taskkill', '/f', '/pid', pid], shell=True)
                        time.sleep(1)
        
        # Also try to kill all Python processes as fallback
        subprocess.run(['taskkill', '/f', '/im', 'python3.13.exe'], shell=True)
        print("Server shutdown complete!")
        
    except Exception as e:
        print(f"Error shutting down server: {e}")
        return False
    
    return True

if __name__ == "__main__":
    shutdown_server()
