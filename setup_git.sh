#!/bin/bash
################################################################################
# Git Setup Assistant - Interactive Guide for Beginners
################################################################################

echo "════════════════════════════════════════════════════════════════════════════════"
echo "           🚀 GIT SETUP ASSISTANT"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Step 1: Check Git Installation
echo -e "${BLUE}[Step 1/9]${NC} Checking Git installation..."
if ! command -v git &> /dev/null; then
    echo -e "${RED}❌ Git is not installed${NC}"
    echo "Installing Git..."
    sudo apt-get update && sudo apt-get install -y git
else
    GIT_VERSION=$(git --version)
    echo -e "${GREEN}✅ $GIT_VERSION${NC}"
fi
echo ""

# Step 2: Configure Git
echo -e "${BLUE}[Step 2/9]${NC} Configuring Git..."

# Check if already configured
CURRENT_NAME=$(git config --global user.name 2>/dev/null)
CURRENT_EMAIL=$(git config --global user.email 2>/dev/null)

if [ -n "$CURRENT_NAME" ] && [ -n "$CURRENT_EMAIL" ]; then
    echo -e "${GREEN}✅ Git already configured:${NC}"
    echo "   Name:  $CURRENT_NAME"
    echo "   Email: $CURRENT_EMAIL"
    echo ""
    read -p "Do you want to change these? (y/n): " CHANGE_CONFIG
    if [ "$CHANGE_CONFIG" != "y" ]; then
        echo "Keeping current configuration."
    else
        CURRENT_NAME=""
        CURRENT_EMAIL=""
    fi
fi

if [ -z "$CURRENT_NAME" ]; then
    echo ""
    read -p "Enter your name (for Git commits): " GIT_NAME
    git config --global user.name "$GIT_NAME"

    read -p "Enter your email (for Git commits): " GIT_EMAIL
    git config --global user.email "$GIT_EMAIL"

    echo -e "${GREEN}✅ Git configured successfully${NC}"
    echo "   Name:  $GIT_NAME"
    echo "   Email: $GIT_EMAIL"
fi
echo ""

# Step 3: Check if already a git repo
echo -e "${BLUE}[Step 3/9]${NC} Checking Git repository..."
if [ -d ".git" ]; then
    echo -e "${YELLOW}⚠️  Git repository already initialized${NC}"

    REMOTE_URL=$(git remote get-url origin 2>/dev/null)
    if [ -n "$REMOTE_URL" ]; then
        echo "   Remote: $REMOTE_URL"
        echo ""
        echo "Repository is already set up!"
        echo "To push changes: git add . && git commit -m 'message' && git push"
        exit 0
    fi
else
    echo "Initializing Git repository..."
    git init
    echo -e "${GREEN}✅ Git repository initialized${NC}"
fi
echo ""

# Step 4: Check .gitignore
echo -e "${BLUE}[Step 4/9]${NC} Checking .gitignore..."
if [ -f ".gitignore" ]; then
    if grep -q ".env" .gitignore; then
        echo -e "${GREEN}✅ .gitignore exists and protects .env${NC}"
    else
        echo -e "${YELLOW}⚠️  Adding .env to .gitignore${NC}"
        echo ".env" >> .gitignore
    fi
else
    echo -e "${YELLOW}⚠️  .gitignore not found (this is unusual)${NC}"
fi
echo ""

# Step 5: Create .env.example if not exists
echo -e "${BLUE}[Step 5/9]${NC} Checking .env.example..."
if [ -f ".env.example" ]; then
    echo -e "${GREEN}✅ .env.example exists${NC}"
else
    echo -e "${YELLOW}⚠️  .env.example not found (this is unusual)${NC}"
fi
echo ""

# Step 6: GitHub Repository URL
echo -e "${BLUE}[Step 6/9]${NC} GitHub Repository Setup"
echo ""
echo "Have you created a repository on GitHub yet?"
echo "If not, go to: https://github.com/new"
echo ""
echo "Repository settings:"
echo "  • Name: smart-contract-scanner"
echo "  • Visibility: Public or Private (your choice)"
echo "  • DO NOT initialize with README"
echo ""
read -p "Press Enter when you've created the repository..."
echo ""

read -p "Enter your GitHub username: " GITHUB_USERNAME
read -p "Enter repository name (default: smart-contract-scanner): " REPO_NAME
REPO_NAME=${REPO_NAME:-smart-contract-scanner}

REPO_URL="https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"
echo ""
echo "Repository URL: $REPO_URL"
echo ""

# Step 7: Stage files
echo -e "${BLUE}[Step 7/9]${NC} Staging files for commit..."

# Check if .env exists and warn
if [ -f ".env" ]; then
    echo -e "${YELLOW}⚠️  WARNING: .env file exists${NC}"
    echo "This file should NOT be committed to GitHub (it contains API keys)"

    if git ls-files --error-unmatch .env > /dev/null 2>&1; then
        echo -e "${RED}❌ .env is tracked by Git!${NC}"
        echo "Removing .env from Git tracking..."
        git rm --cached .env
    fi
fi

echo "Adding files to staging area..."
git add .

# Show status
echo ""
echo "Files to be committed:"
git status --short | head -20
echo ""

STAGED_COUNT=$(git diff --cached --numstat | wc -l)
echo -e "${GREEN}✅ $STAGED_COUNT files staged${NC}"
echo ""

# Step 8: Create commit
echo -e "${BLUE}[Step 8/9]${NC} Creating initial commit..."
echo ""

# Set default branch to main
git branch -M main

git commit -m "Initial commit: Smart Contract Vulnerability Scanner v2.0

- Multi-chain support (8 networks)
- AI-powered validation (GPT-4)
- Real-time WebSocket output
- 80+ vulnerability patterns
- Optimized performance (15-30s scans)
- API-free mode
"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Commit created successfully${NC}"
else
    echo -e "${RED}❌ Commit failed${NC}"
    exit 1
fi
echo ""

# Step 9: Add remote and push
echo -e "${BLUE}[Step 9/9]${NC} Pushing to GitHub..."
echo ""

# Add remote
git remote add origin "$REPO_URL"

echo "Attempting to push to GitHub..."
echo ""
echo -e "${YELLOW}You will be prompted for credentials:${NC}"
echo "  Username: $GITHUB_USERNAME"
echo "  Password: (paste your Personal Access Token)"
echo ""
echo "If you don't have a token yet:"
echo "  1. Go to: https://github.com/settings/tokens"
echo "  2. Generate new token (classic)"
echo "  3. Select 'repo' scope"
echo "  4. Copy the token"
echo ""

git push -u origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo -e "${GREEN}✅ SUCCESS! Your project is now on GitHub!${NC}"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "View your repository at:"
    echo "  https://github.com/$GITHUB_USERNAME/$REPO_NAME"
    echo ""
    echo "Future updates:"
    echo "  git add ."
    echo "  git commit -m 'your message'"
    echo "  git push"
    echo ""
else
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo -e "${RED}❌ Push failed${NC}"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Common issues:"
    echo "  1. Wrong credentials - Make sure to use Personal Access Token (not password)"
    echo "  2. Repository doesn't exist - Create it on GitHub first"
    echo "  3. Wrong repository URL"
    echo ""
    echo "Get help:"
    echo "  • Read: GIT_SETUP_GUIDE.md"
    echo "  • Create token: https://github.com/settings/tokens"
    echo ""
    echo "Try pushing manually:"
    echo "  git push -u origin main"
    echo ""
fi

echo "════════════════════════════════════════════════════════════════════════════════"
