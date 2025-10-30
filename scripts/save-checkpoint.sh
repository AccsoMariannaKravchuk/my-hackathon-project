#!/bin/bash

# Save, commit, push and create checkpoint script
# Usage: ./scripts/save-checkpoint.sh [commit-message]

set -e  # Exit on any error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔄 Starting save-checkpoint workflow...${NC}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "❌ Not in a git repository!"
    exit 1
fi

# Get commit message
COMMIT_MSG="${1:-Auto-save checkpoint: $(date '+%Y-%m-%d %H:%M:%S')}"

# Create timestamp for checkpoint file
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CHECKPOINT_FILE="checkpoint_${TIMESTAMP}.txt"

echo -e "${YELLOW}📋 Adding all changes...${NC}"
git add .

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