import os
import sys
import signal
import subprocess
import time

def shutdown_server():
    print("Attempting to shut down Project Revelare server...")
    
    try:
        if sys.platform == "win32":
            # Find and kill the specific Flask server process
            cmd = "for /f \"tokens=5\" %a in ('netstat -aon ^| findstr :5000') do taskkill /F /PID %a"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        else:
            # Find and kill the process using port 5000 on Linux/macOS
            cmd = "lsof -t -i:5000 | xargs kill -9"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            
        print("Server shutdown signal sent successfully.")
        
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("No active server found on port 5000, or command failed.")
    except Exception as e:
        print(f"An error occurred during shutdown: {e}")
        return False
    
    return True

if __name__ == "__main__":
    shutdown_server()