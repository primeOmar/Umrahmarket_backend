#!/bin/bash

# ===========================================
# SECURE AUTH BACKEND - SETUP SCRIPT
# ===========================================

echo "🔐 Setting up World-Class Secure Authentication Backend..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js is not installed. Please install Node.js >= 18.0.0${NC}"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo -e "${RED}❌ Node.js version 18 or higher is required${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Node.js $(node -v) detected${NC}"

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo -e "${RED}❌ npm is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ npm $(npm -v) detected${NC}"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to install dependencies${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
echo ""

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p logs uploads

echo -e "${GREEN}✅ Directories created${NC}"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠️  No .env file found${NC}"
    echo "Creating .env from .env.example..."
    cp .env.example .env
    
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT: Please configure your .env file with the following:${NC}"
    echo ""
    echo "1. Supabase credentials (SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY)"
    echo "2. Generate JWT secrets with:"
    echo "   node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\""
    echo "3. Set ALLOWED_ORIGINS to your frontend URL(s)"
    echo "4. Configure other settings as needed"
    echo ""
    echo -e "${YELLOW}Press Enter to open .env file in your default editor...${NC}"
    read
    ${EDITOR:-nano} .env
else
    echo -e "${GREEN}✅ .env file exists${NC}"
fi

echo ""

# Generate JWT secrets if not set
if grep -q "your-super-secret-jwt-key" .env 2>/dev/null; then
    echo "🔑 Generating JWT secrets..."
    JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
    JWT_REFRESH_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
    COOKIE_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
    
    # Update .env file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/JWT_SECRET=.*/JWT_SECRET=$JWT_SECRET/" .env
        sed -i '' "s/JWT_REFRESH_SECRET=.*/JWT_REFRESH_SECRET=$JWT_REFRESH_SECRET/" .env
        sed -i '' "s/COOKIE_SECRET=.*/COOKIE_SECRET=$COOKIE_SECRET/" .env
    else
        # Linux
        sed -i "s/JWT_SECRET=.*/JWT_SECRET=$JWT_SECRET/" .env
        sed -i "s/JWT_REFRESH_SECRET=.*/JWT_REFRESH_SECRET=$JWT_REFRESH_SECRET/" .env
        sed -i "s/COOKIE_SECRET=.*/COOKIE_SECRET=$COOKIE_SECRET/" .env
    fi
    
    echo -e "${GREEN}✅ JWT secrets generated and saved to .env${NC}"
fi

echo ""
echo -e "${GREEN}✅ Setup completed successfully!${NC}"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. Configure your .env file with Supabase credentials"
echo "2. Run the database schema in Supabase SQL Editor (database/schema.sql)"
echo "3. Start the development server:"
echo "   npm run dev"
echo ""
echo "4. Test the API:"
echo "   curl http://localhost:5000/health"
echo ""
echo "📚 Documentation:"
echo "   - README.md - Full documentation"
echo "   - SECURITY_CHECKLIST.md - Security audit checklist"
echo "   - SECURITY_IMPLEMENTATION_GUIDE.md - Implementation details"
echo ""
echo -e "${GREEN}🚀 Happy coding with world-class security!${NC}"