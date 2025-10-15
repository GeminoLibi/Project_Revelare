#!/bin/bash

# Project Revelare Backend - Cloudflare Deployment Script
# Deploys the TypeScript backend to Cloudflare Workers

set -e  # Exit on any error

echo "🚀 Project Revelare Backend - Cloudflare Deployment"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if wrangler is installed
if ! command -v wrangler &> /dev/null; then
    print_error "wrangler CLI is not installed. Please install it first:"
    echo "npm install -g wrangler"
    exit 1
fi

# Check if we're in the right directory
if [[ ! -f "wrangler.toml" ]]; then
    print_error "wrangler.toml not found. Please run this script from the cloudflare_backend directory."
    exit 1
fi

# Check if user is logged in to Cloudflare
print_status "Checking Cloudflare authentication..."
if ! wrangler whoami &> /dev/null; then
    print_error "Not logged in to Cloudflare. Please run:"
    echo "wrangler login"
    exit 1
fi

print_success "Cloudflare authentication confirmed"

# Install dependencies
print_status "Installing dependencies..."
npm install

# Build the project
print_status "Building TypeScript project..."
npm run build

# Run type checking
print_status "Running type checking..."
npm run type-check

# Run linting
print_status "Running linting..."
npm run lint

# Create D1 database if it doesn't exist
print_status "Checking D1 database..."
if ! wrangler d1 list | grep -q "project-revelare-db"; then
    print_status "Creating D1 database..."
    wrangler d1 create project-revelare-db

    # Get the database ID and update wrangler.toml
    DB_ID=$(wrangler d1 list | grep "project-revelare-db" | awk '{print $2}')
    if [[ -n "$DB_ID" ]]; then
        sed -i.bak "s/database_id = \".*\"/database_id = \"$DB_ID\"/" wrangler.toml
        print_success "Updated wrangler.toml with database ID: $DB_ID"
    fi
else
    print_success "D1 database already exists"
fi

# Execute database schema
print_status "Setting up database schema..."
wrangler d1 execute project-revelare-db --file=schema.sql

# Check KV namespace
print_status "Checking KV namespace..."
if ! wrangler kv:namespace list | grep -q "REVELARE_KV"; then
    print_status "Creating KV namespace..."
    wrangler kv:namespace create "REVELARE_KV"

    # Get the namespace ID and update wrangler.toml
    KV_ID=$(wrangler kv:namespace list | grep "REVELARE_KV" | awk '{print $2}')
    if [[ -n "$KV_ID" ]]; then
        sed -i.bak "s/id = \".*\"/id = \"$KV_ID\"/" wrangler.toml
        print_success "Updated wrangler.toml with KV namespace ID: $KV_ID"
    fi
else
    print_success "KV namespace already exists"
fi

# Check R2 bucket
print_status "Checking R2 bucket..."
if ! wrangler r2 bucket list | grep -q "revelare-evidence"; then
    print_status "Creating R2 bucket..."
    wrangler r2 bucket create revelare-evidence
else
    print_success "R2 bucket already exists"
fi

# Deploy to staging first (safer)
print_status "Deploying to staging environment..."
wrangler deploy --env staging

# Ask user if they want to deploy to production
read -p "Deploy to production? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Deploying to production..."
    wrangler deploy --env production
    print_success "✅ Deployment to production completed!"
else
    print_success "✅ Deployment to staging completed!"
    echo ""
    echo "To deploy to production later, run:"
    echo "wrangler deploy --env production"
fi

echo ""
echo "🎉 Deployment Summary:"
echo "======================"
echo "• Database: D1 (SQLite-compatible)"
echo "• Storage: R2 bucket for files"
echo "• Sessions: KV namespace for caching"
echo "• API: Cloudflare Workers (global edge deployment)"
echo "• Authentication: JWT with bcrypt hashing"
echo ""
echo "📊 Access your API:"
echo "• Staging: https://staging-api.project-revelare.com"
echo "• Production: https://api.project-revelare.com"
echo "• Documentation: https://api.project-revelare.com/docs"
echo ""
echo "🔐 Default admin account:"
echo "• Email: admin@project-revelare.com"
echo "• Password: admin123"
echo ""
echo "⚠️  IMPORTANT:"
echo "• Update JWT secret in Cloudflare Workers secrets"
echo "• Set up custom domains in Cloudflare"
echo "• Configure CORS origins in production"
echo "• Set up monitoring and alerts"
