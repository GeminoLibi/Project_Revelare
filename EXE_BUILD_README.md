# Building Project Revelare as a Standalone .exe

This guide explains how to package Project Revelare as a Windows executable (.exe) file that can run without Python or any dependencies installed.

## Prerequisites

- Python 3.8 or higher installed
- All project dependencies installed (`pip install -r requirements.txt`)
- PyInstaller installed (`pip install pyinstaller`)

## Quick Build

### Simple Build (Recommended)

1. Open a command prompt in the project directory
2. Run:
   ```batch
   utilities\build_exe.bat
   ```

3. The executable will be created in the `dist` folder as `ProjectRevelare.exe` (that folder is gitignored).

## Manual Build

If you prefer to build manually:

```batch
pyinstaller --clean revelare.spec
```

Or using direct PyInstaller commands:

```batch
pyinstaller --onefile --console --name ProjectRevelare ^
  --add-data "revelare/web/templates;revelare/web/templates" ^
  --add-data "revelare/web/static;revelare/web/static" ^
  --hidden-import flask --hidden-import werkzeug --hidden-import jinja2 ^
  --hidden-import maxminddb revelare_launcher.py
```

## What Gets Included

The executable includes:
- ✅ All Python dependencies (Flask, pandas, numpy, etc.)
- ✅ Flask templates and static files
- ✅ GeoIP databases (if present in project root)
- ✅ All application code
- ✅ Python runtime (no Python installation needed)

## Distribution

To distribute the application:

1. **Single .exe file** (if using one-file mode):
   - Copy `dist/ProjectRevelare.exe` to the target machine
   - That's it! No other files needed.

2. **Directory mode** (if using one-directory mode):
   - Copy the entire `dist/ProjectRevelare` folder
   - Users run `ProjectRevelare.exe` from that folder

3. **Optional files to include**:
   - `cases/` folder (if it contains data)
   - `logs/` folder (if it contains data)
   - `.env` file (for API keys, optional)

## File Size

The executable will be large (typically 100-200 MB) because it includes:
- Python interpreter
- All dependencies
- Application code
- Templates and static files

This is normal for PyInstaller executables.

## Testing the Executable

After building, test the executable:

1. Navigate to the `dist` folder
2. Double-click `ProjectRevelare.exe`
3. Wait for the console window to show "Starting server..."
4. Your browser should automatically open to `http://localhost:5000`
5. Test creating a case and processing files

If templates or static files don't load:
- Check that the files were included in the build
- Verify the paths in `revelare.spec` are correct
- Try rebuilding with `--clean` flag

## Troubleshooting

### "Module not found" errors

If you get import errors, add the missing module to `hiddenimports` in `revelare.spec`:

```python
hiddenimports = [
    # ... existing imports ...
    'missing_module_name',
]
```

### Templates or static files not found

Make sure the data files are correctly specified in `revelare.spec`:

```python
datas = [
    (str(project_root / 'revelare' / 'web' / 'templates'), 'revelare/web/templates'),
    (str(project_root / 'revelare' / 'web' / 'static'), 'revelare/web/static'),
]
```

### Antivirus false positives

Some antivirus software may flag PyInstaller executables as suspicious. This is a known false positive. You can:
- Submit the .exe to your antivirus vendor for whitelisting
- Code sign the executable (requires a certificate)
- Use a different packager (cx_Freeze, py2exe)

### Slow startup time

One-file executables extract to a temporary directory on startup, which can be slow. Options:
- Use one-directory mode (faster startup)
- Use UPX compression (already enabled in spec file)
- Consider using Docker instead for better performance

## Customization

### Change executable name

Edit `revelare.spec`:
```python
exe = EXE(
    # ...
    name='YourCustomName',  # Change this
    # ...
)
```

### Add an icon

1. Create or obtain a `.ico` file
2. Edit `revelare.spec`:
```python
exe = EXE(
    # ...
    icon='path/to/icon.ico',  # Add this
    # ...
)
```

### Windowed mode (no console)

Edit `revelare.spec`:
```python
exe = EXE(
    # ...
    console=False,  # Change to False
    # ...
)
```

## Comparison: .exe vs Docker

| Feature | .exe File | Docker |
|---------|-----------|--------|
| **Ease of use** | ⭐⭐⭐⭐⭐ Double-click to run | ⭐⭐⭐⭐ Requires Docker |
| **File size** | ⭐⭐ Large (100-200 MB) | ⭐⭐⭐⭐ Small (just code) |
| **Startup speed** | ⭐⭐⭐ Slower (extracts on first run) | ⭐⭐⭐⭐⭐ Fast |
| **Dependencies** | ⭐⭐⭐⭐⭐ None needed | ⭐⭐⭐ Docker required |
| **Cross-platform** | ⭐⭐ Windows only | ⭐⭐⭐⭐⭐ All platforms |
| **Distribution** | ⭐⭐⭐⭐⭐ Single file | ⭐⭐⭐⭐ Share folder |

**Recommendation**: Use .exe for Windows-only distribution to non-technical users. Use Docker for cross-platform or technical users.

## Notes

- The executable will create `cases/`, `logs/`, and `temp/` directories in the same folder as the .exe
- Database files are stored in the `logs/` directory
- The web interface runs on `http://localhost:5000` (or next available port)
- All functionality works the same as the Python version
