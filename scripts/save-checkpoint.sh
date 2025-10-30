#!/bin/bash

# Save, commit, push and create checkpoint script
# Usage: ./scripts/save-checkpoint.sh [commit-message]

set -e  # Exit on any error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔄 Starting save-checkpoint workflow with quality checks...${NC}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}❌ Not in a git repository!${NC}"
    exit 1
fi

# Function to kill any running servers
cleanup_servers() {
    echo -e "${YELLOW}🧹 Cleaning up any running servers...${NC}"
    pkill -f "node src/server.js" 2>/dev/null || true
    sleep 1
}

# Get commit message
COMMIT_MSG="${1:-Auto-save checkpoint: $(date '+%Y-%m-%d %H:%M:%S')}"

# Create timestamp for checkpoint file
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CHECKPOINT_FILE="checkpoint_${TIMESTAMP}.txt"

echo -e "${YELLOW}📋 Adding all changes...${NC}"
git add .

echo -e "${BLUE}🧪 Running quality checks before commit...${NC}"

# 1. Run tests
echo -e "${YELLOW}📝 Running tests...${NC}"
if npm test; then
    echo -e "${GREEN}✅ All tests pass${NC}"
else
    echo -e "${RED}❌ Tests failed! Aborting save.${NC}"
    exit 1
fi

# 2. Check code style
echo -e "${YELLOW}🎨 Checking code style...${NC}"
if npm run lint; then
    echo -e "${GREEN}✅ Code style consistent${NC}"
else
    echo -e "${RED}❌ Linting failed! Aborting save.${NC}"
    exit 1
fi

# 3. Start app and test
echo -e "${YELLOW}🚀 Testing app startup...${NC}"
cleanup_servers

# Start server in background
npm start &
SERVER_PID=$!
sleep 3

# Check if server is running
if ps -p $SERVER_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✅ App starts without errors${NC}"
    
    # 4. Basic smoke test
    echo -e "${YELLOW}🔍 Running smoke test...${NC}"
    if curl -f -s http://localhost:3000 > /dev/null; then
        echo -e "${GREEN}✅ Basic smoke test passed${NC}"
    else
        echo -e "${RED}❌ Smoke test failed! Server not responding.${NC}"
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi
    
    # Kill the test server
    kill $SERVER_PID 2>/dev/null || true
    sleep 1
else
    echo -e "${RED}❌ App failed to start! Aborting save.${NC}"
    exit 1
fi

echo -e "${GREEN}🎉 All quality checks passed!${NC}"

echo -e "${YELLOW}💾 Committing changes...${NC}"
git commit -m "$COMMIT_MSG"

echo -e "${YELLOW}🚀 Pushing to GitHub...${NC}"
git push

echo -e "${YELLOW}📄 Creating checkpoint file...${NC}"
cat > "$CHECKPOINT_FILE" << EOF
# Checkpoint Created: $(date)
# Commit: $(git rev-parse HEAD)
# Branch: $(git branch --show-current)
# Files changed in this session:

$(git diff --name-only HEAD~1 2>/dev/null || echo "Initial commit")

# Project Status:
- Server running: $(pgrep -f "node src/server.js" > /dev/null && echo "✅ Yes" || echo "❌ No")
- Port 3000 status: $(lsof -i :3000 > /dev/null 2>&1 && echo "✅ Active" || echo "❌ Free")

# Quick Commands:
# Start server: npm start
# Run tests: npm test  
# Check status: git status
EOF

echo -e "${GREEN}✅ All changes saved, committed, pushed, and checkpoint created!${NC}"
echo -e "${GREEN}📄 Checkpoint file: ${CHECKPOINT_FILE}${NC}"
echo -e "${GREEN}🔗 GitHub: https://github.com/AccsoMariannaKravchuk/my-hackathon-project${NC}"