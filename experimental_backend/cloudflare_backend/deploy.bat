@echo off
REM Project Revelare Backend - Windows Deployment Script
REM Deploys to Cloudflare Workers from Windows

echo 🚀 Project Revelare Backend - Cloudflare Deployment (Windows)
echo ===========================================================

REM Check if we're in the right directory
if not exist "wrangler.toml" (
    echo ❌ wrangler.toml not found. Please run this from the cloudflare_backend directory.
    pause
    exit /b 1
)

REM Install dependencies
echo 📦 Installing dependencies...
call npm install

REM Build the project
echo 🔨 Building TypeScript project...
call npm run build

REM Set JWT secret
echo 🔑 Setting JWT secret...
echo Paste this secret when prompted:
echo f94116b2817bc40e2c64e552d2a929953b81130d6f392b935aabdac7357c96cd8ff43c78309cb9e178d61b47a880c84d6c4ac2e0eaf6cbc9a461d1ce8d835a36
wrangler secret put JWT_SECRET

REM Deploy to staging
echo 🚀 Deploying to staging...
wrangler deploy --env staging

echo.
echo 🎉 Deployment Complete!
echo ======================
echo ✅ Backend deployed to: https://staging-api.project-revelare.com
echo ✅ API Documentation: https://staging-api.project-revelare.com/docs
echo ✅ Health Check: https://staging-api.project-revelare.com/health
echo.
echo 🔐 Default admin account:
echo    Email: admin@project-revelare.com
echo    Password: admin123
echo.
echo Next steps:
echo 1. Test the API endpoints
echo 2. Set up custom domains in Cloudflare Dashboard
echo 3. Deploy to production: wrangler deploy --env production
echo.
pause
