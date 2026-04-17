# Click2Fix Patch Workbench Min: Installation And Configuration (Zero-To-Run)

This document is the complete install and configuration guide for the **Patch Workbench minimal package** (single-page patch UI + global shell + execution status/history).

Use this file for both Linux and Windows hosts.

## 1) What This Min Build Includes

- Frontend (`c2f-frontend`)
- Nginx API gateway (`c2f-lb`)
- Backend API (`backend`)
- PostgreSQL (`db`)
- Redis (`redis`)

This min build does **not** include the full multi-module frontend or v2 bounded-service backend stack.

## 2) Prerequisites

- Docker Engine 24+ (or Docker Desktop current)
- Docker Compose plugin (`docker compose`)
- Host with at least:
  - 4 vCPU
  - 8 GB RAM
  - 25 GB free disk
- Network path from this host to:
  - Wazuh Manager API
  - Wazuh Indexer API
  - Windows endpoints (WinRM)
  - Linux endpoints (SSH)

## 3) Required Ports And Connectivity

### Inbound to the Patch Workbench host

- `5173/tcp` - Frontend UI (`C2F_FRONTEND_PORT`)
- `8000/tcp` - Backend via Nginx (`C2F_BACKEND_PORT`) - optional to expose publicly
- `5432/tcp` - PostgreSQL mapped port (`C2F_DB_PORT`) - keep internal/restricted

### Outbound from the Patch Workbench host

- `55000/tcp` - Wazuh Manager API (`WAZUH_URL`)
- `9200/tcp` - Wazuh Indexer API (`INDEXER_URL`)
- `5985/tcp` and/or `5986/tcp` - WinRM endpoints
- `22/tcp` - Linux SSH endpoints
- `443/tcp` - GHCR/GitHub (if pulling/downloading online)

## 4) Credentials You Need Before Install

- Wazuh Manager API user/password
- Wazuh Indexer user/password
- Local Click2Fix admin username/password
- Endpoint connector credentials:
  - Windows WinRM service account
  - Linux SSH account(s), optionally per-agent

## 5) Environment Configuration (Mandatory)

Create `.env.patch-workbench` from template:

```bash
cp .env.patch-workbench.template .env.patch-workbench
```

Minimum required keys:

```env
# Images
C2F_BACKEND_IMAGE=ghcr.io/<owner>/click2fix-backend-min
C2F_FRONTEND_IMAGE=ghcr.io/<owner>/click2fix-frontend-min
C2F_IMAGE_TAG=1.1.12
C2F_SKIP_PULL=false

# UI/API ports
C2F_FRONTEND_PORT=5173
C2F_BACKEND_PORT=8000

# Database + auth
POSTGRES_PASSWORD=<strong-db-password>
JWT_SECRET=<long-random-secret>
C2F_BOOTSTRAP_ADMIN_USERNAME=admin
C2F_BOOTSTRAP_ADMIN_PASSWORD=<strong-admin-password>

# Wazuh
WAZUH_URL=https://<wazuh-manager-ip>:55000
WAZUH_USER=<wazuh-api-user>
WAZUH_PASSWORD=<wazuh-api-password>
INDEXER_URL=https://<wazuh-indexer-ip>:9200
INDEXER_USER=<indexer-user>
INDEXER_PASSWORD=<indexer-password>

# Connector toggles
C2F_WINDOWS_CONNECTOR_ENABLED=true
C2F_LINUX_CONNECTOR_ENABLED=true
```

## 6) Endpoint Connector Configuration (WinRM + SSH)

### Windows (global)

```env
C2F_WINDOWS_CONNECTOR_ENABLED=true
C2F_WINRM_USERNAME=DOMAIN\svc_click2fix
C2F_WINRM_PASSWORD=<password>
```

### Windows (per-agent override)

```env
C2F_WINRM_USERNAME_001=DOMAIN\svc_agent_001
C2F_WINRM_PASSWORD_001=<password-001>
```

### Linux (global)

```env
C2F_LINUX_CONNECTOR_ENABLED=true
C2F_SSH_USERNAME=ubuntu
C2F_SSH_PASSWORD=<password>
```

### Linux (per-agent override, recommended for mixed passwords)

```env
C2F_SSH_USERNAME_004=turabit
C2F_SSH_PASSWORD_004=<password-004>
```

Notes:

- Agent ID suffix must be normalized 3-digit form (for example `004`, `129`).
- Use per-agent vars when credentials differ across endpoints.
- For Linux patch commands, do not type password in command text. Use `Run as admin` and connector credentials.

## 7) Download + Install Methods (Ubuntu/Linux)

## Method A: Release ZIP (recommended)

```bash
VERSION=min-v1.1.12
OWNER=helisudani0
REPO=click2fix

curl -fL -o click2fix-patch-workbench-installer-${VERSION}.zip \
  https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/click2fix-patch-workbench-installer-${VERSION}.zip

curl -fL -o click2fix-patch-workbench-installer-${VERSION}.sha256 \
  https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/click2fix-patch-workbench-installer-${VERSION}.sha256

sha256sum -c click2fix-patch-workbench-installer-${VERSION}.sha256
mkdir -p /opt/click2fix-patch-workbench
unzip -o click2fix-patch-workbench-installer-${VERSION}.zip -d /opt/click2fix-patch-workbench
cd /opt/click2fix-patch-workbench
cp .env.patch-workbench.template .env.patch-workbench
./install-patch-workbench.sh
```

## Method B: Raw bootstrap script (command-only)

```bash
VERSION=min-v1.1.12
curl -fsSL "https://raw.githubusercontent.com/helisudani0/click2fix/${VERSION}/deploy/appliance/bootstrap-patch-workbench.sh" \
  -o ./bootstrap-patch-workbench.sh
chmod +x ./bootstrap-patch-workbench.sh
OWNER=helisudani0 REPO=click2fix VERSION=${VERSION} INSTALL_DIR=/opt/click2fix-patch-workbench PULL_IMAGES=true \
  ./bootstrap-patch-workbench.sh
```

## Method C: Clone repo and run directly

```bash
git clone https://github.com/helisudani0/click2fix.git
cd click2fix
git checkout patch-workbench-min
cd deploy/appliance
cp .env.patch-workbench.template .env.patch-workbench
./install-patch-workbench.sh
```

## Method D: Offline/image-transfer

On source host:

```bash
cd deploy/appliance
./build-local-images.sh
./export-images.sh ./click2fix-min-images.tar
```

On destination host:

```bash
cd /opt/click2fix-patch-workbench
./import-images.sh ./click2fix-min-images.tar
```

Then set:

```env
C2F_SKIP_PULL=true
```

and run `./install-patch-workbench.sh`.

## 8) Download + Install Methods (Windows)

## Method A: Release ZIP + PowerShell installer

```powershell
$Version = "min-v1.1.12"
$Owner = "helisudani0"
$Repo = "click2fix"
$Base = "https://github.com/$Owner/$Repo/releases/download/$Version"

Invoke-WebRequest "$Base/click2fix-patch-workbench-installer-$Version.zip" -OutFile ".\click2fix-patch-workbench-installer-$Version.zip"
Invoke-WebRequest "$Base/click2fix-patch-workbench-installer-$Version.sha256" -OutFile ".\click2fix-patch-workbench-installer-$Version.sha256"

Expand-Archive ".\click2fix-patch-workbench-installer-$Version.zip" -DestinationPath "C:\Click2Fix-PatchWorkbench" -Force
Set-Location "C:\Click2Fix-PatchWorkbench"
Copy-Item .env.patch-workbench.template .env.patch-workbench -Force
powershell -ExecutionPolicy Bypass -File .\install-patch-workbench.ps1
```

## Method B: Raw bootstrap (command-only)

```powershell
$Version = "min-v1.1.12"
Invoke-WebRequest "https://raw.githubusercontent.com/helisudani0/click2fix/$Version/deploy/appliance/bootstrap-patch-workbench.ps1" -OutFile .\bootstrap-patch-workbench.ps1
powershell -ExecutionPolicy Bypass -File .\bootstrap-patch-workbench.ps1 -Owner helisudani0 -Repo click2fix -Version $Version -InstallDir C:\Click2Fix-PatchWorkbench -PullImages
```

## Method C: Git clone + installer

```powershell
git clone https://github.com/helisudani0/click2fix.git C:\click2fix
cd C:\click2fix
git checkout patch-workbench-min
cd deploy\appliance
Copy-Item .env.patch-workbench.template .env.patch-workbench -Force
powershell -ExecutionPolicy Bypass -File .\install-patch-workbench.ps1
```

## 9) Post-Install Validation

```bash
docker compose --env-file .env.patch-workbench -f docker-compose.patch-workbench.yml ps
```

Check UI:

- `http://<host>:5173`

Check API docs:

- `http://<host>:8000/docs`

Quick Linux connector validation:

- Select Linux agent
- Choose `Bash`
- Enable `Run as admin`
- Run: `id -u`
- Expected success output should include `0` for root context

## 10) Operations

Linux:

```bash
./manage-patch-workbench.sh
./upgrade-patch-workbench.sh
```

Windows:

```powershell
.\manage-patch-workbench.ps1
.\upgrade-patch-workbench.ps1
```

## 11) Security And Hardening

- Rotate all default secrets before production use.
- Restrict inbound DB/API ports with firewall rules.
- Use least-privilege service accounts for WinRM/SSH.
- Prefer per-agent credentials for mixed endpoint fleets.
- Keep `.env.patch-workbench` file permission-restricted.
- Do not embed passwords in shell commands.

