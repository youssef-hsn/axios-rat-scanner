#!/bin/bash
PROJECTS_DIR="${1:-.}"
FOUND=0

echo "🔍 Scanning: $PROJECTS_DIR"
echo "========================================"

# Step 1a: Check package-lock.json (npm)
echo ""
echo "[ 1/4 ] Checking package-lock.json for malicious axios (npm)..."
while IFS= read -r -d '' lockfile; do
  dir=$(dirname "$lockfile")
  match=$(grep -A1 '"axios"' "$lockfile" 2>/dev/null | grep -E "1\.14\.1|0\.30\.4")
  if [ -n "$match" ]; then
    echo "  ❌ FOUND in: $dir"
    echo "     $match"
    FOUND=1
  fi
done < <(find "$PROJECTS_DIR" -name "package-lock.json" -not -path "*/node_modules/*" -print0)

# Step 1b: Check pnpm-lock.yaml (pnpm)
echo ""
echo "[ 2/4 ] Checking pnpm-lock.yaml for malicious axios (pnpm)..."
while IFS= read -r -d '' lockfile; do
  dir=$(dirname "$lockfile")
  match=$(grep -E "axios@.*1\.14\.1|axios@.*0\.30\.4|/axios@1\.14\.1|/axios@0\.30\.4" "$lockfile" 2>/dev/null)
  if [ -n "$match" ]; then
    echo "  ❌ FOUND in: $dir"
    echo "     $match"
    FOUND=1
  fi
done < <(find "$PROJECTS_DIR" -name "pnpm-lock.yaml" -not -path "*/node_modules/*" -print0)

# Step 2: Check for plain-crypto-js directory (both npm and pnpm layouts)
echo ""
echo "[ 3/4 ] Checking for plain-crypto-js in node_modules..."
while IFS= read -r dir; do
  echo "  ❌ DROPPER RAN in: $dir"
  FOUND=1
done < <(find "$PROJECTS_DIR" -type d -name "plain-crypto-js" -path "*/node_modules/*" 2>/dev/null)

# Step 3: Check for RAT artifact
echo ""
echo "[ 4/4 ] Checking for macOS RAT artifact..."
if [ -f "/Library/Caches/com.apple.act.mond" ]; then
  echo "  ❌ RAT BINARY FOUND: /Library/Caches/com.apple.act.mond"
  ls -la /Library/Caches/com.apple.act.mond
  FOUND=1
fi

# Summary
echo ""
echo "========================================"
if [ "$FOUND" -eq 0 ]; then
  echo "✅ No indicators of compromise found."
else
  echo "🚨 POTENTIAL COMPROMISE DETECTED — see above."
  echo ""
  echo "Next steps:"
  echo "  1. Treat affected machines as fully compromised"
  echo "  2. Rotate ALL credentials (npm, AWS, SSH keys, .env secrets, CI/CD tokens)"
  echo "  3. Remove the RAT: rm -f /Library/Caches/com.apple.act.mond"
  echo "  4. Downgrade axios: npm install axios@1.14.0  OR  pnpm add axios@1.14.0"
  echo "  5. Remove the package: rm -rf <project>/node_modules/plain-crypto-js"
  echo "  6. Reinstall safely: npm ci --ignore-scripts  OR  pnpm install --ignore-scripts"
fi
