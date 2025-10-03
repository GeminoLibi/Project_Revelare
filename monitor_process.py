#!/usr/bin/env python3
"""
Process Monitor for Project Revelare
Provides diagnostics to determine if the extraction process is hung or just processing large files.
"""

import os
import sys
import time
import psutil
from datetime import datetime, timezone
# Use standard logger access, imported from our tuned logger module
from logger import get_logger 

# Initialize logger (optional, but good practice)
logger = get_logger('monitor')

def monitor_revelare_process():
    """Monitor the current Revelare process and show status."""
    print("🔍 Project Revelare Process Monitor")
    print("=" * 50)
    
    # --- 1. Process Monitoring ---
    revelare_processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_info', 'create_time']):
        try:
            # Check for Python processes running relevant keywords
            process_name_lower = proc.info['name'].lower()
            if 'python' in process_name_lower or 'revelare' in process_name_lower:
                cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                # Look for keywords that indicate the process is running the application core
                if 'revelare' in cmdline.lower() or 'extractor' in cmdline.lower() or 'cli' in cmdline.lower():
                    # Call .cpu_percent() once to prime the values for accurate reading
                    proc.cpu_percent(interval=None) 
                    revelare_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    if not revelare_processes:
        print("❌ No active Revelare processes found.")
        return
    
    print(f"Found {len(revelare_processes)} Revelare process(es):")
    
    for i, proc in enumerate(revelare_processes, 1):
        try:
            # Re-read CPU percentage with a short interval for fresh data
            cpu_percent = proc.cpu_percent(interval=0.1) 
            memory_info = proc.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            # Use UTC timezone for forensic consistency
            create_time = datetime.fromtimestamp(proc.info['create_time'], tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            uptime = datetime.now(timezone.utc) - datetime.fromtimestamp(proc.info['create_time'], tz=timezone.utc)
            
            print(f"\nProcess {i} (PID: {proc.info['pid']}):")
            print(f"  Uptime: {uptime}")
            print(f"  Start Time: {create_time}")
            print(f"  CPU Load: {cpu_percent:.1f}%")
            print(f"  Memory (RSS): {memory_mb:.1f} MB")
            # Truncate command for clean output
            print(f"  Command: {' '.join(proc.info['cmdline'])[:80]}...")
            
            # Diagnostic status based on resource usage
            if cpu_percent > 10.0:
                print(f"  🔴 Status: **HIGH ACTIVITY** (Extraction is running full speed)")
            elif cpu_percent > 0.5 and memory_mb > 250:
                print(f"  🟡 Status: **PROCESSING LARGE FILE** (Low CPU, high memory suggests deep scanning)")
            elif cpu_percent < 0.1 and uptime.total_seconds() > 60:
                print(f"  ❓ Status: **POSSIBLY HUNG** (Process is idle for too long)")
            else:
                 print(f"  ✅ Status: **IDLE/AWAITING INPUT** (Or just started)")
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as e:
            print(f"  ❌ Error accessing process data: {e}")
            
    # --- 2. Log Activity Monitoring ---
    
    # Use the hardened log file name (from logger.py tune-up: revelare_audit.log)
    log_file = "revelare_audit.log" 
    if os.path.exists(log_file):
        print("\n📋 Recent Audit Log Activity:")
        print("-" * 50)
        
        try:
            # Open with 'ignore' errors for potentially corrupt log files
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Read from the end of the file for the last 15 lines
                lines = f.readlines()
                recent_lines = lines[-15:] if len(lines) >= 15 else lines
            
            for line in recent_lines:
                line = line.strip()
                if line:
                    # Simple color coding based on log level presence
                    if 'CRITICAL' in line or 'SECURITY ALERT' in line:
                        print(f"🔴 {line}")
                    elif 'ERROR' in line:
                        print(f"🔴 {line}")
                    elif 'WARNING' in line:
                        print(f"🟡 {line}")
                    elif 'INFO' in line:
                        print(f"🔵 {line}")
                    else:
                        print(f"⚪ {line}")
        except Exception as e:
            print(f"❌ Error reading log file: {e}")
    
    print("\n💡 Monitoring Tips:")
    print("  - Look for **Chunked processing** or **Heartbeat** messages in the log.")
    print("  - Low CPU + High Memory indicates normal **deep file scanning**.")
    print("  - Constant High CPU indicates **high-speed pattern matching**.")

if __name__ == "__main__":
    try:
        monitor_revelare_process()
    except KeyboardInterrupt:
        print("\n\n👋 Monitor stopped by user.")
    except Exception as e:
        print(f"\n❌ Unhandled error in monitor: {e}")