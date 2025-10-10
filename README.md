Of course. Based on the complete, refactored application, here are the updated `README.md` and a newly generated `requirements.txt` file.

-----

### Updated `README.md`

This version reflects the final file structure, the new `start.py` launcher, and the features we improved.

````markdown
# Project Revelare - Documentation

This documentation covers Project Revelare v2.5, an advanced digital forensics and data extraction platform. It features a unified web and command-line interface, intelligent evidence processing, and comprehensive case management.

## 🚀 Quick Start

The recommended way to run the application is via the unified launcher.

```bash
# From the project root directory
python start.py
````

This will present an interactive menu with the following options:

  * **[1] Launch Web Interface**: Starts the Flask server and opens the GUI in your browser.
  * **[2] Launch Command Line Interface (CLI)**: Opens an interactive shell for direct commands.
  * **[3] Run Case Onboarding Wizard**: A guided setup for creating a new case.
  * **[4] Run String Search Tool**: A prompt-based tool for finding strings in a project.
  * **[5] Run Email Archive Analyzer**: A prompt-based tool for analyzing email archives.
  * **[6] Access Fractal Encryption Tool**: Instructions on how to use this feature via the web UI.

-----

## 🔧 Installation

### Prerequisites

  * Python 3.8+
  * **Tesseract OCR Engine** (for image-to-text functionality)
      * **Windows**: Download from [Tesseract at UB Mannheim](https://github.com/UB-Mannheim/tesseract/wiki)
      * **macOS**: `brew install tesseract`
      * **Linux**: `sudo apt install tesseract-ocr`

### Installation Steps

1.  Navigate to the project's root directory.
2.  Install all required Python packages using the `requirements.txt` file:

<!-- end list -->

```bash
pip install -r requirements.txt
```

3.  Verify the installation by running the launcher:

<!-- end list -->

```bash
python start.py
```

-----

## 📁 Final Project Structure

```
/project_revelare/
├── cases/
│   └── (Generated automatically for case data)
├── logs/
│   └── (Generated automatically for logs and database)
├── revelare/
│   ├── cli/
│   │   ├── revelare_cli.py
│   │   └── suite.py
│   ├── config/
│   │   └── config.py
│   ├── core/
│   │   ├── case_manager.py
│   │   ├── data_enhancer.py
│   │   ├── enrichers.py
│   │   ├── extractor.py
│   │   ├── file_processors.py
│   │   └── validators.py
│   ├── utils/
│   │   ├── file_extractor.py
│   │   ├── fractal_encryption.py
│   │   ├── geoip_service.py
│   │   ├── logger.py
│   │   ├── mbox_viewer.py
│   │   ├── reporter.py
│   │   ├── revelare_onboard.py
│   │   ├── security.py
│   │   └── string_search.py
│   └── web/
│       ├── static/
│       │   ├── css/
│       │   │   └── style.css
│       │   └── js/
│       │       ├── main.js
│       │       └── report.js
│       └── templates/
│           ├── (all .html files)
├── launch_gui.py
├── launch_web.py
├── requirements.txt
├── shutdown_server.py
├── start.py
└── README.md
```

-----

## 🔍 Features

### Core Capabilities

  * **Unified Interface**: Access all features through a clean web UI or a powerful command-line interface, launched from a single `start.py` script.
  * **Case Management**: Create, manage, and add evidence to structured case folders.
  * **Automated Processing**: Evidence files are processed in the background, keeping the UI responsive.
  * **Multi-Format Support**: Handles over 50 file types, including automatic extraction of ZIP, RAR, and 7Z archives.
  * **Advanced IOC Extraction**: Extracts 20+ indicator types (IPs, emails, URLs, metadata, financial data, etc.) using regex patterns defined in `config.py`.
  * **OCR & Transcription**: Extracts text from images and PDFs using Tesseract and transcribes audio from media files using Whisper.

### Forensic Tools

  * **Link Analysis (Enhanced)**: Visually graphs connections between cases. Automatically discovers not only direct links but also "second-degree" connections (related cases that share other indicators).
  * **String Search (Enhanced)**: An advanced tool to find specific text within all files of a project, now with support for both literal strings and **Regular Expressions**.
  * **Email Browser**: A dedicated interface to parse, view, and analyze email archives (MBOX, EML, PST) found within cases.
  * **Fractal Encryption**: A unique steganography tool to encrypt and hide files within the structure of a fractal image.

### Reporting & Security

  * **Multi-Page Reports**: Generates comprehensive, interactive HTML reports with filterable tables for indicators, files, geolocation, and more.
  * **Secure by Design**: Includes robust input validation, path traversal protection, secure file handling, and prevention against common web vulnerabilities.

<!-- end list -->

````
