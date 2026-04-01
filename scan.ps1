param(
    [string]$ProjectsDir = "."
)

$Found = 0

Write-Host "`nScanning: $ProjectsDir" -ForegroundColor Cyan
Write-Host "========================================"

# Step 1/4: Check package-lock.json (npm)
Write-Host "`n[ 1/4 ] Checking package-lock.json for malicious axios (npm)..."
Get-ChildItem -Path $ProjectsDir -Recurse -Filter "package-lock.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "node_modules" } |
    ForEach-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match '"axios"[\s\S]*?(1\.14\.1|0\.30\.4)') {
            $dir = $_.DirectoryName
            Write-Host "  FOUND in: $dir" -ForegroundColor Red
            Write-Host "     Matched version: $($Matches[1])" -ForegroundColor Red
            $script:Found = 1
        }
    }

# Step 2/4: Check pnpm-lock.yaml (pnpm)
Write-Host "`n[ 2/4 ] Checking pnpm-lock.yaml for malicious axios (pnpm)..."
Get-ChildItem -Path $ProjectsDir -Recurse -Filter "pnpm-lock.yaml" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "node_modules" } |
    ForEach-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match 'axios@.*(1\.14\.1|0\.30\.4)|/axios@(1\.14\.1|0\.30\.4)') {
            $dir = $_.DirectoryName
            Write-Host "  FOUND in: $dir" -ForegroundColor Red
            Write-Host "     Matched: $($Matches[0])" -ForegroundColor Red
            $script:Found = 1
        }
    }

# Step 3/4: Check for plain-crypto-js directory
Write-Host "`n[ 3/4 ] Checking for plain-crypto-js in node_modules..."
Get-ChildItem -Path $ProjectsDir -Recurse -Directory -Filter "plain-crypto-js" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like "node_modules" } |
    ForEach-Object {
        Write-Host "  DROPPER RAN in: $($_.FullName)" -ForegroundColor Red
        $script:Found = 1
    }

# Step 4/4: Check for RAT artifact (Windows equivalent path + original macOS path)
Write-Host "`n[ 4/4 ] Checking for RAT artifacts..."
$ratPaths = @(
    "/Library/Caches/com.apple.act.mond",
    "$env:ProgramData\com.apple.act.mond",
    "$env:LOCALAPPDATA\com.apple.act.mond"
)
foreach ($ratPath in $ratPaths) {
    if (Test-Path $ratPath -ErrorAction SilentlyContinue) {
        Write-Host "  RAT BINARY FOUND: $ratPath" -ForegroundColor Red
        Get-Item $ratPath | Format-List Name, Length, LastWriteTime
        $script:Found = 1
    }
}

# Summary
Write-Host "`n========================================"
if ($Found -eq 0) {
    Write-Host "No indicators of compromise found." -ForegroundColor Green
} else {
    Write-Host "POTENTIAL COMPROMISE DETECTED -- see above." -ForegroundColor Red
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Treat affected machines as fully compromised"
    Write-Host "  2. Rotate ALL credentials (npm, AWS, SSH keys, .env secrets, CI/CD tokens)"
    Write-Host "  3. Remove the RAT binary if found"
    Write-Host "  4. Downgrade axios: npm install axios@1.14.0  OR  pnpm add axios@1.14.0"
    Write-Host "  5. Remove the package: Remove-Item -Recurse -Force <project>\node_modules\plain-crypto-js"
    Write-Host "  6. Reinstall safely: npm ci --ignore-scripts  OR  pnpm install --ignore-scripts"
}
