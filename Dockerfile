FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p cases logs temp

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV REVELARE_HOST=0.0.0.0
ENV REVELARE_PORT=5000
ENV REVELARE_UPLOAD_FOLDER=/app/cases
ENV REVELARE_DATABASE=/app/logs/revelare_master.db

# Expose port
EXPOSE 5000

# Default command - launch web interface
CMD ["python", "launch_web.py"]
