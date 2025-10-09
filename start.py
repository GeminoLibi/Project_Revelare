#!/usr/bin/env python3
"""
Project Revelare - Unified Launcher
A single entry point that provides access to all Revelare functionality.
"""

import sys
import os
import subprocess
from pathlib import Path

# Add the revelare package to Python path
project_root = Path(__file__).parent
revelare_path = project_root / "revelare"
sys.path.insert(0, str(project_root))

def print_header():
    """Display the welcome header."""
    print("=" * 60)
    print("     PROJECT REVELARE v2.5.0")
    print("    Advanced Digital Forensics Platform")
    print("=" * 60)
    print()

def display_menu():
    """Display the main menu options."""
    print("Choose your interface:")
    print()
    print("  [1] WEB INTERFACE (Browser-based GUI)")
    print("      - User-friendly web dashboard")
    print("      - Real-time progress monitoring")
    print("      - File upload and processing")
    print("      - Report viewing and export")
    print()
    print("  [2] COMMAND LINE INTERFACE (CLI)")
    print("      - Direct file processing")
    print("      - Batch operations")
    print("      - Scripting and automation")
    print()
    print("  [3] QUICK START (Interactive Onboarding)")
    print("      - Guided case setup wizard")
    print("      - Project structure creation")
    print("      - Evidence file organization")
    print()
    print("  [4] STRING SEARCH TOOL")
    print("      - Search for specific strings in files")
    print("      - Regex pattern matching")
    print("      - Context-aware results")
    print()
    print("  [5] EMAIL BROWSER")
    print("      - Analyze email archives (MBOX, Maildir, EML, PST)")
    print("      - Extract email metadata")
    print("      - Generate email reports")
    print()
    print("  [6] FRACTAL ENCRYPTION TOOL")
    print("      - Encrypt files into fractal images")
    print("      - Advanced steganography")
    print("      - Visual data hiding")
    print()
    print("  [Q] QUIT")
    print()
    print("-" * 60)

def get_user_choice():
    """Get and validate user menu choice."""
    while True:
        try:
            choice = input("Enter your choice [1-6 or Q]: ").strip().upper()

            if choice in ['1', '2', '3', '4', '5', '6', 'Q']:
                return choice
            else:
                print("Invalid choice. Please enter 1-6 or Q.")
                print()

        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            sys.exit(0)
        except EOFError:
            print("\n\nGoodbye!")
            sys.exit(0)

def launch_web_interface():
    """Launch the web interface."""
    print("Starting Web Interface...")
    print("   Press Ctrl+C to stop the server")
    print()

    try:
        # Import the web launcher function
        from revelare.cli.suite import launch_web_app
        from revelare.config.config import Config

        # Set development mode if requested
        debug_mode = '--debug' in sys.argv or '-d' in sys.argv

        # Launch the web app (this will handle port finding and browser opening)
        success = launch_web_app(
            host=Config.HOST,
            port=Config.PORT,
            debug=debug_mode,
            open_browser_flag=True
        )

        if not success:
            print("Failed to start web interface")
            sys.exit(1)

    except Exception as e:
        print(f"Error starting web interface: {e}")
        print("Make sure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        sys.exit(1)

def launch_cli_interface():
    """Launch the command line interface."""
    print("Starting Command Line Interface...")
    print()
    print("Project Revelare CLI provides direct file processing capabilities.")
    print("You can now enter CLI commands directly:")
    print()
    print("Examples:")
    print("  --onboard                    # Interactive case onboarding")
    print("  -p \"case_001\" -f evidence.zip   # Process files")
    print("  --add-files \"case_001\" --files new.zip  # Add to existing case")
    print("  --help                       # Show full help")
    print()
    print("Enter your CLI command (or 'quit' to return to main menu):")

    try:
        # Import and run the CLI
        from revelare.cli.revelare_cli import main as cli_main

        # Get CLI command from user
        while True:
            try:
                cli_command = input("CLI> ").strip()
                if cli_command.lower() in ['quit', 'q', 'exit']:
                    print("Returning to main menu...")
                    return

                if cli_command:
                    # Parse the command and set sys.argv
                    import shlex
                    cli_args = shlex.split(cli_command)
                    sys.argv = ['revelare_cli.py'] + cli_args

                    # Run the CLI command
                    result = cli_main()

                    # If command was successful and not onboarding, return to menu
                    if result == 0:
                        print("\nCLI command completed successfully.")
                        input("Press Enter to continue...")
                        break
                    else:
                        print(f"\nCLI command exited with code: {result}")
                        input("Press Enter to try another command...")
                else:
                    print("Please enter a CLI command or 'quit' to return to main menu.")

            except KeyboardInterrupt:
                print("\nReturning to main menu...")
                return
            except EOFError:
                print("\nReturning to main menu...")
                return

    except Exception as e:
        print(f"Error starting CLI: {e}")
        input("Press Enter to continue...")
        return

def launch_onboarding():
    """Launch the interactive onboarding wizard."""
    print("Starting Interactive Onboarding...")
    print()

    try:
        # Import and run the CLI with onboard flag
        from revelare.cli.revelare_cli import main as cli_main

        sys.argv = ['revelare_cli.py', '--onboard']
        sys.exit(cli_main())

    except Exception as e:
        print(f"Error starting onboarding: {e}")
        sys.exit(1)

def launch_string_search():
    """Launch the string search tool."""
    print("Starting String Search Tool...")
    print()

    try:
        # Import and run the string search
        from revelare.utils.string_search import main as search_main

        # Remove our script arguments and pass remaining args
        search_args = sys.argv[1:]
        sys.argv = ['string_search.py'] + search_args

        sys.exit(search_main())

    except Exception as e:
        print(f"Error starting string search: {e}")
        sys.exit(1)

def launch_email_browser():
    """Launch the email browser."""
    print("Starting Email Browser...")
    print()

    try:
        # Import and run the email browser
        from revelare.utils.mbox_viewer import main as email_main

        # Remove our script arguments and pass remaining args
        email_args = sys.argv[1:]
        sys.argv = ['mbox_viewer.py'] + email_args

        sys.exit(email_main())

    except Exception as e:
        print(f"Error starting email browser: {e}")
        sys.exit(1)

def launch_fractal_encryption():
    """Launch the fractal encryption tool."""
    print("Starting Fractal Encryption Tool...")
    print("Hide files within fractal images using advanced steganography")
    print()

    try:
        # Import and run the fractal CLI
        from revelare.cli.fractal_cli import main as fractal_main

        # Remove our script arguments and pass remaining args
        fractal_args = sys.argv[1:]
        sys.argv = ['fractal_cli.py'] + fractal_args

        sys.exit(fractal_main())

    except ImportError as e:
        print(f"Error: Could not import fractal encryption module: {e}")
        print("Make sure all dependencies are installed.")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting fractal encryption: {e}")
        sys.exit(1)

def check_dependencies():
    """Check if required dependencies are available."""
    missing_deps = []

    try:
        import flask
    except ImportError:
        missing_deps.append("flask")

    try:
        import pypdf
    except ImportError:
        missing_deps.append("pypdf")

    try:
        import pandas  # pyright: ignore[reportMissingImports]
    except ImportError:
        missing_deps.append("pandas")

    try:
        import openpyxl
    except ImportError:
        missing_deps.append("openpyxl")

    try:
        import requests
    except ImportError:
        missing_deps.append("requests")

    if missing_deps:
        print("Warning: Missing optional dependencies detected:")
        for dep in missing_deps:
            print(f"   - {dep}")
        print()
        print("Some features may not work. Install with:")
        print("  pip install -r requirements.txt")
        print()
        return False

    return True

def main():
    """Main launcher function."""
    # Enable debug mode if requested
    debug_mode = '--debug' in sys.argv or '-d' in sys.argv or '--verbose' in sys.argv or '-v' in sys.argv

    if debug_mode:
        print("DEBUG: Debug mode enabled")
        print(f"DEBUG: Python path: {sys.path[:3]}...")
        print(f"DEBUG: Current directory: {os.getcwd()}")
        print(f"DEBUG: Command line args: {sys.argv}")
        print()

    # Check dependencies first
    if not check_dependencies():
        if debug_mode:
            print("DEBUG: Dependency check completed with warnings")
        else:
            print("Some optional dependencies are missing. Continuing anyway...")

    # Display header and menu
    print_header()
    display_menu()

    # Get user choice
    choice = get_user_choice()

    if debug_mode:
        print(f"DEBUG: User selected choice: {choice}")

    # Launch appropriate interface
    if choice == '1':
        if debug_mode:
            print("DEBUG: Launching web interface...")
        launch_web_interface()
    elif choice == '2':
        if debug_mode:
            print("DEBUG: Launching CLI interface...")
        launch_cli_interface()
    elif choice == '3':
        if debug_mode:
            print("DEBUG: Launching onboarding...")
        launch_onboarding()
    elif choice == '4':
        if debug_mode:
            print("DEBUG: Launching string search...")
        launch_string_search()
    elif choice == '5':
        if debug_mode:
            print("DEBUG: Launching email browser...")
        launch_email_browser()
    elif choice == '6':
        if debug_mode:
            print("DEBUG: Launching fractal encryption...")
        launch_fractal_encryption()
    elif choice == 'Q':
        print("Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        print("Please check the logs for more details.")
        sys.exit(1)
