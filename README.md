# axios-rat-scanner

Scans your local projects for signs of compromise from the malicious `axios@1.14.1` and `axios@0.30.4` npm packages published on March 30, 2026. These versions injected a hidden dependency (`plain-crypto-js@4.2.1`) that dropped a cross-platform Remote Access Trojan (RAT).

Supports projects using **npm** and **pnpm**.

> Full incident writeup: [StepSecurity Blog](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

---

## What it checks

1. `package-lock.json` and `pnpm-lock.yaml` for malicious axios versions (`1.14.1`, `0.30.4`)
2. `node_modules/plain-crypto-js` — presence of this directory means the dropper ran
3. Platform-specific RAT artifacts left on disk

---

## Usage

### macOS / Linux

```bash
bash scan.sh /path/to/your/projects
```

### Windows (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File scan.ps1 -ProjectsDir "C:\path\to\your\projects"
```

Omit the path argument to scan the current directory.

---

## What to do if compromised

1. **Treat the machine as fully compromised** — do not attempt to clean in place
2. **Rotate all credentials** — npm tokens, AWS keys, SSH keys, `.env` secrets, CI/CD tokens
3. **Downgrade axios**
   ```bash
   npm install axios@1.14.0
   # or
   pnpm add axios@1.14.0
   ```
4. **Remove the malicious package**
   ```bash
   rm -rf node_modules/plain-crypto-js   # macOS/Linux
   rd /s /q node_modules\plain-crypto-js  # Windows
   ```
5. **Reinstall dependencies with scripts disabled**
   ```bash
   npm ci --ignore-scripts
   # or
   pnpm install --ignore-scripts
   ```
6. **Remove RAT artifacts**
   ```bash
   rm -f /Library/Caches/com.apple.act.mond          # macOS
   rm -f /tmp/ld.py                                    # Linux
   del "%PROGRAMDATA%\wt.exe"                          # Windows
   ```
7. **Audit CI/CD pipelines** — rotate secrets in any pipeline that ran `npm install` with the affected versions

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Malicious packages | `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1` |
| C2 domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| macOS RAT | `/Library/Caches/com.apple.act.mond` |
| Linux RAT | `/tmp/ld.py` |
| Windows RAT | `%PROGRAMDATA%\wt.exe` |

---

## Safe versions

- `axios@1.14.0` (1.x users)
- `axios@0.30.3` (0.x users)
