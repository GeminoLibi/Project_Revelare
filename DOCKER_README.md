# Docker Setup for Project Revelare

This guide explains how to run Project Revelare using Docker, which eliminates the need for users to install Python or any dependencies.

## Prerequisites

- Docker Desktop installed on your system
  - Windows: Download from [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)
  - Mac: Download from [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop)
  - Linux: Install Docker Engine and Docker Compose

## Quick Start

### All Platforms

Using Docker Compose (recommended):
```bash
docker-compose up -d
```

The web interface will be available at: **http://localhost:5000**

## Docker Commands

### Start the container
```bash
docker-compose up -d
```

### View logs
```bash
docker-compose logs -f
```

### Stop the container
```bash
docker-compose down
```

### Rebuild the container (after code changes)
```bash
docker-compose up -d --build
```

### Run CLI commands
```bash
# Create a new case
docker-compose exec revelare python -m revelare.cli.revelare_cli --onboard

# Process files
docker-compose exec revelare python -m revelare.cli.revelare_cli -p "case_001" -f evidence.zip
```

## Data Persistence

The following directories are mounted as volumes, so your data persists even if you remove the container:

- `./cases` - All case data and processed files
- `./logs` - Application logs and database
- `./temp` - Temporary files

## Environment Variables

You can customize the configuration by creating a `.env` file in the project root. The container will automatically load it. See `env.template` for available options.

Example `.env`:
```env
REVELARE_PORT=5000
REVELARE_HOST=0.0.0.0
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

## Troubleshooting

### Port 5000 already in use

Edit `docker-compose.yml` and change the port mapping:
```yaml
ports:
  - "8080:5000"  # Use port 8080 instead
```

Then access at http://localhost:8080

### Container won't start

Check the logs:
```bash
docker-compose logs
```

### Permission issues (Linux/Mac)

If you encounter permission issues with mounted volumes:
```bash
sudo chown -R $USER:$USER cases logs temp
```

### Rebuild from scratch

If you need to completely rebuild:
```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

## Sharing with Others

To share Project Revelare with others who don't have Python installed:

1. Share the entire project directory (or a zip of it)
2. They just need Docker installed
3. They run `docker-compose up -d`
4. No Python, pip, or dependency installation needed!

## Manual Docker Run (without docker-compose)

If you prefer not to use docker-compose:

```bash
# Build the image
docker build -t project-revelare .

# Run the container
docker run -d \
  -p 5000:5000 \
  -v $(pwd)/cases:/app/cases \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/temp:/app/temp \
  --name project_revelare \
  project-revelare
```

## Notes

- The container runs the web interface by default
- All dependencies are included in the container
- GeoIP databases (if present) are included in the image
- Case data, logs, and temp files are stored on your host machine via volumes
