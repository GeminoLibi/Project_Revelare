# Project Revelare Web Interface

This directory contains the web interface components for Project Revelare, a digital forensics and data extraction tool.

## Directory Structure

```
web/
├── templates/           # HTML templates
│   ├── base.html       # Base template with navigation and layout
│   ├── dashboard.html  # Main dashboard for project management
│   ├── link_analysis.html  # Cross-project indicator search
│   ├── string_search.html  # String search within projects
│   └── mbox_viewer.html    # MBOX email archive viewer
├── static/             # Static assets
│   ├── css/
│   │   └── style.css   # Main stylesheet
│   ├── js/
│   │   └── main.js     # JavaScript functionality
│   └── images/         # Image assets (if any)
└── README.md          # This file
```

## Features

### Dashboard (`/`)
- Upload new evidence files for analysis
- View existing projects and their status
- Access project reports and exports
- Real-time project status updates

### Link Analysis (`/link_analysis`)
- Search for specific indicators across all projects
- Find connections between different cases
- Cross-reference findings from multiple evidence sources

### String Search (`/string_search`)
- Search for specific strings within project files
- Support for archive files (ZIP, RAR, 7Z)
- Context display around matches
- File type filtering

### MBOX Viewer (`/mbox_viewer`)
- Analyze email archives in MBOX format
- Search through email content and headers
- Export analysis results
- Contact and timeline analysis

## Usage

### Starting the Web Interface

1. **Using the launcher script:**
   ```bash
   python launch_web.py
   ```

2. **Using the main module:**
   ```bash
   python -m revelare_core web
   ```

3. **Direct Flask execution:**
   ```bash
   python suite.py
   ```

### Accessing the Interface

Once started, open your web browser and navigate to:
- **Local:** http://localhost:5000
- **Network:** http://[your-ip]:5000

## Configuration

The web interface uses the main Project Revelare configuration from `config.py`:

- **Host:** `Config.HOST` (default: localhost)
- **Port:** `Config.PORT` (default: 5000)
- **Upload Folder:** `Config.UPLOAD_FOLDER` (default: ../cases)
- **Database:** `Config.DATABASE` (default: ../../logs/revelare_master.db)

## Templates

### Base Template (`base.html`)
- Common layout and navigation
- Flash message handling
- Responsive design
- Font Awesome icons

### Dashboard Template (`dashboard.html`)
- Project upload form with drag-and-drop
- Project grid display
- Status indicators
- Feature showcase

### Link Analysis Template (`link_analysis.html`)
- Search form for indicators
- Results display
- Cross-project navigation
- Search tips and help

### String Search Template (`string_search.html`)
- Project selection
- Search string configuration
- File extension filtering
- Context window settings

### MBOX Viewer Template (`mbox_viewer.html`)
- File upload interface
- Analysis options
- Search configuration
- Feature documentation

## Static Assets

### CSS (`css/style.css`)
- Modern, responsive design
- Project Revelare branding
- Interactive elements
- Mobile-friendly layout

### JavaScript (`js/main.js`)
- File upload handling
- Form validation
- Interactive features
- Loading states

## Security Features

- Input validation and sanitization
- Path traversal protection
- File type restrictions
- CSRF protection (Flask built-in)
- Secure file serving

## Browser Compatibility

- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+

## Development

### Adding New Pages

1. Create a new template in `templates/`
2. Add a route in `suite.py`
3. Update navigation in `base.html`
4. Add any required static assets

### Modifying Styles

Edit `css/style.css` and refresh the browser. The Flask development server will automatically reload changes.

### Adding JavaScript

Edit `js/main.js` or create new JavaScript files in the `static/js/` directory.

## Troubleshooting

### Common Issues

1. **Template not found:** Ensure the template file exists in `templates/` directory
2. **Static files not loading:** Check that the `static/` directory structure is correct
3. **Database errors:** Verify database configuration and permissions
4. **Upload failures:** Check file size limits and upload folder permissions

### Debug Mode

Enable debug mode by setting `Config.DEBUG = True` in `config.py` for detailed error messages and automatic reloading.

## License

Part of Project Revelare - Digital Forensics and Data Extraction Tool
