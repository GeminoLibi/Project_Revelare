#!/bin/bash

# Simple Cloudflare Deployment Script
# Run this script to deploy Project Revelare backend to Cloudflare

echo "🚀 Deploying Project Revelare Backend to Cloudflare..."
echo "======================================================"

# Check if wrangler is installed
if ! command -v wrangler &> /dev/null; then
    echo "❌ Wrangler CLI not found. Installing..."
    npm install -g wrangler
fi

# Check if we're logged in
echo "🔐 Checking Cloudflare authentication..."
if ! wrangler whoami &> /dev/null; then
    echo "❌ Not logged in to Cloudflare."
    echo "Please run: wrangler login"
    echo "Then run this script again."
    exit 1
fi

echo "✅ Cloudflare authentication confirmed"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Build the project
echo "🔨 Building TypeScript project..."
npm run build

# Set JWT secret
echo "🔑 Setting JWT secret..."
echo "Paste this secret when prompted:"
echo "f94116b2817bc40e2c64e552d2a929953b81130d6f392b935aabdac7357c96cd8ff43c78309cb9e178d61b47a880c84d6c4ac2e0eaf6cbc9a461d1ce8d835a36"
wrangler secret put JWT_SECRET

# Deploy to staging first
echo "🚀 Deploying to staging..."
wrangler deploy --env staging

echo ""
echo "🎉 Deployment Complete!"
echo "======================="
echo "✅ Backend deployed to: https://staging-api.project-revelare.com"
echo "✅ API Documentation: https://staging-api.project-revelare.com/docs"
echo "✅ Health Check: https://staging-api.project-revelare.com/health"
echo ""
echo "🔐 Default admin account:"
echo "   Email: admin@project-revelare.com"
echo "   Password: admin123"
echo ""
echo "Next steps:"
echo "1. Test the API endpoints"
echo "2. Set up custom domains in Cloudflare Dashboard"
echo "3. Deploy to production: wrangler deploy --env production"
