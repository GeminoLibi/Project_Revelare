import os
import sys
import subprocess
import time

# Add the project root directory to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def get_script_path(script_name):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    locations = [
        os.path.join(base_dir, script_name),
        os.path.join(base_dir, 'revelare', 'cli', script_name),
        os.path.join(base_dir, 'revelare', 'utils', script_name)
    ]
    
    for path in locations:
        if os.path.exists(path):
            return path
            
    return None

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_menu():
    clear_screen()
    print("=" * 50)
    print("  Project Revelare - Unified Launcher")
    print("=" * 50)
    print("\n  [1] Launch Web Interface")
    print("  [2] Launch Command Line Interface (CLI)")
    print("  [3] Run Case Onboarding Wizard (Quick Start)")
    print("  [4] Run String Search Tool")
    print("  [5] Run Email Archive Analyzer")
    print("  [6] Access Fractal Encryption Tool")
    print("\n  [Q] Quit")
    print("-" * 50)

def launch_web_interface():
    print("\nLaunching Web Interface...")
    script_path = get_script_path('launch_web.py')
    if not script_path:
        print("\nERROR: launch_web.py not found.")
        return
    try:
        subprocess.run([sys.executable, script_path], check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"\nError launching web interface: {e}")
    except KeyboardInterrupt:
        print("\nWeb server stopped by user.")

def launch_cli():
    print("\nLaunching Command Line Interface...")
    script_path = get_script_path('revelare_cli.py')
    if not script_path:
        print("\nERROR: revelare_cli.py not found.")
        return
    try:
        subprocess.run([sys.executable, script_path])
    except Exception as e:
        print(f"\nError launching CLI: {e}")

def run_onboarding():
    print("\nStarting Case Onboarding Wizard...")
    script_path = get_script_path('revelare_cli.py')
    if not script_path:
        print("\nERROR: revelare_cli.py not found.")
        return
    try:
        subprocess.run([sys.executable, script_path, '--onboard'])
    except Exception as e:
        print(f"\nError running onboarding: {e}")

def run_string_search():
    clear_screen()
    print("--- String Search Tool ---")
    directory = input("Enter the full path to the project directory to search: ").strip()
    if not os.path.isdir(directory):
        print("\nERROR: Invalid directory path.")
        return
        
    search_terms = input("Enter search strings (comma-separated): ").strip()
    if not search_terms:
        print("\nERROR: At least one search string is required.")
        return
        
    script_path = get_script_path('string_search.py')
    if not script_path:
        print("\nERROR: string_search.py not found.")
        return

    command = [sys.executable, script_path, directory, '-s'] + [term.strip() for term in search_terms.split(',')]
    print("\nRunning search...")
    subprocess.run(command)

def run_email_analyzer():
    clear_screen()
    print("--- Email Archive Analyzer ---")
    mbox_file = input("Enter the full path to the email archive file (e.g., .mbox, .eml): ").strip()
    if not os.path.isfile(mbox_file):
        print("\nERROR: File not found.")
        return
        
    output_file = input("Enter path for the output report (e.g., report.html): ").strip()
    
    script_path = get_script_path('mbox_viewer.py')
    if not script_path:
        print("\nERROR: mbox_viewer.py not found.")
        return

    command = [sys.executable, script_path, 'analyze', mbox_file, '-o', output_file]
    print("\nRunning analysis...")
    subprocess.run(command)

def access_fractal_tool():
    print("\n--- Fractal Encryption Tool ---")
    print("This tool is available through the Web Interface.")
    print("\n  1. Select Option [1] to launch the Web Interface.")
    print("  2. Navigate to the 'Fractal Encryption' page from the main menu.")

def main():
    while True:
        print_menu()
        choice = input("Enter your choice: ").strip().lower()
        
        if choice == '1':
            launch_web_interface()
        elif choice == '2':
            launch_cli()
        elif choice == '3':
            run_onboarding()
        elif choice == '4':
            run_string_search()
        elif choice == '5':
            run_email_analyzer()
        elif choice == '6':
            access_fractal_tool()
        elif choice in ['q', 'quit', 'exit']:
            print("\nExiting Project Revelare Launcher. Goodbye!")
            break
        else:
            print("\nInvalid choice. Please try again.")
        
        input("\nPress Enter to return to the menu...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nLauncher interrupted. Exiting.")