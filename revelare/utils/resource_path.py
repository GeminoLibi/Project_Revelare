"""
Utility for handling resource paths in both normal Python and PyInstaller executables
"""
import sys
import os
from pathlib import Path

def resource_path(relative_path):
    """
    Get absolute path to resource, works for dev and for PyInstaller
    
    Args:
        relative_path: Path relative to the project root
        
    Returns:
        Absolute path to the resource
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        # Running as normal Python script
        base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    return os.path.join(base_path, relative_path)

def get_template_folder():
    """Get the template folder path, works for both normal and PyInstaller execution"""
    if getattr(sys, 'frozen', False):
        # Running as compiled exe
        try:
            base_path = sys._MEIPASS
            template_path = os.path.join(base_path, 'revelare', 'web', 'templates')
            if os.path.exists(template_path):
                return template_path
        except AttributeError:
            pass
    
    # Fallback to normal path
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 
                       'revelare', 'web', 'templates')

def get_static_folder():
    """Get the static folder path, works for both normal and PyInstaller execution"""
    if getattr(sys, 'frozen', False):
        # Running as compiled exe
        try:
            base_path = sys._MEIPASS
            static_path = os.path.join(base_path, 'revelare', 'web', 'static')
            if os.path.exists(static_path):
                return static_path
        except AttributeError:
            pass
    
    # Fallback to normal path
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 
                       'revelare', 'web', 'static')
