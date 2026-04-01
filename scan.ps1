param(
    [string]$ProjectsDir = "."
)

$Found = 0

# Exclude lockfiles under node_modules (parity with scan.sh find -not -path "*/node_modules/*")
function Test-OutsideNodeModules {
    param([string]$FullName)
    $FullName -notmatch '[\\/]node_modules[\\/]'
}

Write-Host "`nScanning: $ProjectsDir" -ForegroundColor Cyan
Write-Host "========================================"

# Step 1/6: Check package-lock.json (npm)
Write-Host "`n[ 1/6 ] Checking package-lock.json for malicious axios (npm)..."
Get-ChildItem -Path $ProjectsDir -Recurse -Filter "package-lock.json" -File -ErrorAction SilentlyContinue |
    Where-Object { Test-OutsideNodeModules $_.FullName } |
    ForEach-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match '"axios"[\s\S]*?(1\.14\.1|0\.30\.4)') {
            $dir = $_.DirectoryName
            Write-Host "  FOUND in: $dir" -ForegroundColor Red
            Write-Host "     Matched version: $($Matches[1])" -ForegroundColor Red
            $script:Found = 1
        }
    }

# Step 2/6: Check pnpm-lock.yaml (pnpm)
Write-Host "`n[ 2/6 ] Checking pnpm-lock.yaml for malicious axios (pnpm)..."
Get-ChildItem -Path $ProjectsDir -Recurse -Filter "pnpm-lock.yaml" -File -ErrorAction SilentlyContinue |
    Where-Object { Test-OutsideNodeModules $_.FullName } |
    ForEach-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match 'axios@.*(1\.14\.1|0\.30\.4)|/axios@(1\.14\.1|0\.30\.4)') {
            $dir = $_.DirectoryName
            Write-Host "  FOUND in: $dir" -ForegroundColor Red
            Write-Host "     Matched: $($Matches[0])" -ForegroundColor Red
            $script:Found = 1
        }
    }

# Step 3/6: Check yarn.lock (Yarn classic + Berry)
Write-Host "`n[ 3/6 ] Checking yarn.lock for malicious axios (yarn)..."
Get-ChildItem -Path $ProjectsDir -Recurse -Filter "yarn.lock" -File -ErrorAction SilentlyContinue |
    Where-Object { Test-OutsideNodeModules $_.FullName } |
    ForEach-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        # Classic: .../axios-1.14.1.tgz — Berry: axios@npm:1.14.1 / "axios@npm:1.14.1"
        if ($content -match 'axios-1\.14\.1\.tgz|axios-0\.30\.4\.tgz|axios@npm:1\.14\.1|axios@npm:0\.30\.4|"axios@npm:1\.14\.1"|"axios@npm:0\.30\.4"') {
            $dir = $_.DirectoryName
            Write-Host "  FOUND in: $dir" -ForegroundColor Red
            Write-Host "     Matched: $($Matches[0])" -ForegroundColor Red
            $script:Found = 1
        }
    }

# Step 4/6: Check bun.lock (text) and bun.lockb (binary)
Write-Host "`n[ 4/6 ] Checking bun.lock / bun.lockb for malicious axios (bun)..."
@('bun.lock', 'bun.lockb') | ForEach-Object {
    $bunName = $_
    Get-ChildItem -Path $ProjectsDir -Recurse -Filter $bunName -File -ErrorAction SilentlyContinue |
        Where-Object { Test-OutsideNodeModules $_.FullName }
} | ForEach-Object {
        $dir = $_.DirectoryName
        $hit = $false
        $matched = $null
        if ($_.Extension -eq '.lockb') {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
                $latin1 = [System.Text.Encoding]::GetEncoding('iso-8859-1')
                $content = $latin1.GetString($bytes)
                if ($content -match 'axios@(1\.14\.1|0\.30\.4)([^0-9.]|$)|axios/1\.14\.1|axios/0\.30\.4|"axios".*1\.14\.1|"axios".*0\.30\.4') {
                    $hit = $true
                    $matched = $Matches[0]
                }
            }
            catch {
                # unreadable file; skip
            }
        }
        else {
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match '"axios"[\s\S]*?(1\.14\.1|0\.30\.4)') {
                $hit = $true
                $matched = "version: $($Matches[1])"
            }
        }
        if ($hit) {
            Write-Host "  FOUND in: $dir" -ForegroundColor Red
            Write-Host "     Matched: $matched" -ForegroundColor Red
            $script:Found = 1
        }
    }

# Step 5/6: Check for plain-crypto-js directory
Write-Host "`n[ 5/6 ] Checking for plain-crypto-js in node_modules..."
Get-ChildItem -Path $ProjectsDir -Recurse -Directory -Filter "plain-crypto-js" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '[\\/]node_modules[\\/]' } |
    ForEach-Object {
        Write-Host "  DROPPER RAN in: $($_.FullName)" -ForegroundColor Red
        $script:Found = 1
    }

# Step 6/6: Check for RAT artifact (Windows equivalent path + original macOS path)
Write-Host "`n[ 6/6 ] Checking for RAT artifacts..."
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
    Write-Host "  4. Downgrade axios: npm install axios@1.14.0  |  pnpm add axios@1.14.0  |  yarn add axios@1.14.0  |  bun add axios@1.14.0"
    Write-Host "  5. Remove the package: Remove-Item -Recurse -Force <project>\node_modules\plain-crypto-js"
    Write-Host "  6. Reinstall safely: npm ci --ignore-scripts  |  pnpm install --ignore-scripts  |  yarn install --ignore-scripts  |  bun install --ignore-scripts"
}
