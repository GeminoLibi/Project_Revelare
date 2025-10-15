# Project Revelare - Experimental Backend

A modern, secure, and scalable backend for digital forensics and investigation platform.

## 🚀 Overview

This experimental backend represents a complete architectural overhaul of the Project Revelare system, featuring:

- **Modern Architecture**: Layered architecture with clear separation of concerns
- **Security First**: JWT authentication, RBAC, file validation, and security scanning
- **Scalable Design**: Async processing, connection pooling, and efficient resource management
- **Comprehensive API**: RESTful API with proper versioning and documentation
- **Production Ready**: Proper logging, monitoring, health checks, and error handling

## 🏗️ Architecture

```
experimental_backend/
├── src/
│   ├── api/                 # FastAPI application layer
│   │   ├── routes/         # API route handlers
│   │   ├── models/         # Pydantic request/response models
│   │   ├── dependencies/   # FastAPI dependencies
│   │   └── middleware/     # Custom middleware
│   ├── core/               # Business logic layer
│   │   ├── services/       # Core services
│   │   ├── processors/     # File processing logic
│   │   └── validators/     # Input validation
│   ├── database/           # Database layer
│   │   ├── models/         # SQLAlchemy models
│   │   ├── repositories/   # Data access layer
│   │   └── migrations/     # Database migrations
│   └── utils/              # Utility functions
├── config.py               # Configuration management
├── main.py                 # Application entry point
└── requirements.txt        # Dependencies
```

## 🔧 Key Features

### Authentication & Security
- **JWT-based authentication** with access and refresh tokens
- **Role-based access control (RBAC)** with user tiers (hobbyist, professional, enterprise, admin)
- **Password hashing** using bcrypt
- **Account lockout** after failed login attempts
- **Multi-factor authentication** support
- **Security headers** and CORS protection
- **Rate limiting** to prevent abuse

### Database Layer
- **SQLAlchemy 2.0** with async support
- **Connection pooling** for performance
- **Comprehensive models** for Users, Cases, Evidence, Findings
- **Audit trails** and soft deletion support
- **Transaction management**

### API Layer
- **FastAPI** with automatic OpenAPI documentation
- **Proper middleware** for security, logging, and error handling
- **Rate limiting** and request validation
- **Structured error responses**
- **Health checks** and monitoring endpoints

### File Processing
- **Secure file upload** with validation and virus scanning
- **Multiple file type support** (documents, archives, emails, images, etc.)
- **Asynchronous processing** with progress tracking
- **Metadata extraction** and content analysis
- **Findings generation** and enrichment

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- SQLite (or PostgreSQL for production)

### Installation

1. **Clone and navigate to the experimental backend:**
   ```bash
   cd experimental_backend
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Initialize the database:**
   ```bash
   python -c "from src.database.session import db_manager; db_manager.create_tables()"
   ```

5. **Start the development server:**
   ```bash
   python main.py
   ```

The API will be available at:
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **API Base**: http://localhost:8000/api/v1

## 🔐 Authentication

### Register a new user:
```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "securepassword123",
    "agency": "Digital Forensics Lab"
  }'
```

### Login and get tokens:
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

### Use JWT token in requests:
```bash
curl -X GET "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 📋 API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login and get tokens
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - Logout and revoke tokens
- `GET /api/v1/users/me` - Get current user profile

### Cases
- `POST /api/v1/cases` - Create new case
- `GET /api/v1/cases` - List user's cases
- `GET /api/v1/cases/{case_id}` - Get case details
- `PUT /api/v1/cases/{case_id}` - Update case
- `DELETE /api/v1/cases/{case_id}` - Delete case

### Evidence
- `POST /api/v1/cases/{case_id}/evidence` - Upload evidence files
- `GET /api/v1/cases/{case_id}/evidence` - List evidence files
- `GET /api/v1/evidence/{evidence_id}` - Get evidence file details
- `DELETE /api/v1/evidence/{evidence_id}` - Delete evidence file

### Analysis
- `POST /api/v1/cases/{case_id}/analyze` - Start analysis
- `GET /api/v1/cases/{case_id}/status` - Get analysis status
- `GET /api/v1/cases/{case_id}/findings` - Get analysis findings
- `GET /api/v1/cases/{case_id}/report` - Get analysis report

## 🔧 Configuration

### Environment Variables

```bash
# Security
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# API Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=true

# Database
DATABASE_URL=sqlite:///./revelare.db

# File Processing
UPLOAD_DIR=./uploads
MAX_FILE_SIZE=2147483648
TEMP_DIR=./temp
RESULTS_DIR=./results

# Security Scanning
VIRUS_SCAN_ENABLED=true
MALWARE_HASHES_API=your-malware-api-key

# External Services (Optional)
OPENAI_API_KEY=your-openai-key
SENDGRID_API_KEY=your-sendgrid-key
TURNSTILE_SECRET_KEY=your-turnstile-key

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/revelare.log
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/test_api/
pytest tests/test_core/
pytest tests/test_database/

# Run with coverage
pytest --cov=src tests/

# Run integration tests
pytest tests/test_integration/
```

## 🚀 Deployment

### Development
```bash
python main.py
```

### Production (Docker)
```bash
docker build -t revelare-backend .
docker run -p 8000:8000 revelare-backend
```

### Production (Systemd)
```bash
# Copy service file
sudo cp scripts/revelare.service /etc/systemd/system/

# Enable and start service
sudo systemctl enable revelare
sudo systemctl start revelare
```

## 📊 Monitoring

### Health Checks
- **Application Health**: `/health`
- **Database Status**: `/api/v1/health/database`
- **File System Status**: `/api/v1/health/storage`

### Metrics
- **Request/Response times**
- **Error rates**
- **Database connection pools**
- **File processing statistics**

### Logging
- **Structured JSON logging**
- **Rotating file handlers**
- **Error tracking with Sentry** (optional)

## 🔒 Security Features

- **Input validation** with Pydantic models
- **SQL injection protection** with SQLAlchemy
- **XSS protection** with security headers
- **CSRF protection** with proper CORS configuration
- **File upload security** with type validation and virus scanning
- **Rate limiting** to prevent abuse
- **Audit logging** for all user actions
- **Secure password storage** with bcrypt hashing

## 🎯 Performance Optimizations

- **Connection pooling** for database connections
- **Asynchronous processing** for file analysis
- **Caching** for frequently accessed data
- **Compression** for API responses
- **Efficient queries** with proper indexing
- **Background job processing** for heavy operations

## 🔄 Migration from Legacy Backend

1. **Backup existing data**
2. **Install new dependencies**
3. **Run database migrations**
4. **Import existing cases and users**
5. **Update client applications**
6. **Test thoroughly**
7. **Switch traffic to new backend**

## 📚 Documentation

- **API Documentation**: Available at `/docs` when running
- **Architecture Guide**: See `docs/architecture.md`
- **Development Guide**: See `docs/development.md`
- **Deployment Guide**: See `docs/deployment.md`

## 🤝 Contributing

1. Follow the existing code style
2. Write tests for new features
3. Update documentation
4. Use conventional commits
5. Ensure all tests pass

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check existing documentation
- Review the troubleshooting guide

---

**Built with ❤️ for digital forensics professionals**
