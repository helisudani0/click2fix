# Click2Fix Appliance Deployment (OVA-Oriented)

This folder is the customer-facing deployment scaffold for the current Click2Fix appliance line.

For environments that cannot execute PowerShell scripts, use the CMD-only operational guide:

- `deploy/appliance/CMD_INSTALL_AND_MANAGE.md`

The intended current flows:

1. Customer runs the Docker-based appliance scaffold directly from release assets or the raw bootstrap path.
2. Or, maintainer builds a VM/OVA from the same appliance files and uses the existing first-boot wizard inside the VM.

## Direct Customer Download (GitHub Releases)

Once a release tag is published (for example `v1.2.0`), customers can download directly from:

- `https://github.com/<owner>/<repo>/releases/latest`
- or pinned release:
  - `https://github.com/<owner>/<repo>/releases/tag/v1.2.0`

Download asset:

- `click2fix-appliance-installer-v1.2.0.zip` (name varies by release tag)

Current `v1.1.4` appliance scope:

- runtime services: `postgres`, `redis`, `backend`, `c2f-lb` (nginx), `frontend`
- published Click2Fix images: backend + frontend only (redis/nginx are public images)
- `agent-manager`, `event-indexer`, and other v2 bounded services are not part of the current appliance release

Separate install tracks:

- Main appliance: `install.sh` / `install.ps1` using `docker-compose.appliance.yml` and `.env.appliance`.
- Patch Workbench appliance: `install-patch-workbench.sh` / `install-patch-workbench.ps1` using `docker-compose.patch-workbench.yml` and `.env.patch-workbench`.
- Main installer no longer prompts for edition. Patch Workbench is enabled only through the dedicated patch-workbench compose/install files.

## Files

- `docker-compose.appliance.yml`
  - Image-based runtime (no source code mounts, no local dev workflow).
- `docker-compose.patch-workbench.yml`
  - Dedicated compose stack for the minimal Patch Workbench package (forces patch-workbench backend/frontend mode).
- `.env.appliance.template`
  - Customer config template with placeholders.
- `.env.patch-workbench.template`
  - Separate customer config template used by patch-workbench install path.
- `install.sh`
  - Interactive first-boot setup and launch script.
- `install.ps1`
  - Interactive first-boot setup and launch script for Windows hosts.
- `install-patch-workbench.sh`
  - Interactive first-boot setup for Patch Workbench package on Linux hosts.
- `install-patch-workbench.ps1`
  - Interactive first-boot setup for Patch Workbench package on Windows hosts.
- `setup.sh` / `setup.cmd`
  - One-click launcher wrappers for installers.
- `manage.sh` / `manage.cmd` / `manage.ps1`
  - Control Center (start/stop/restart/status/logs/upgrade/show access URLs).
- `manage-patch-workbench.sh` / `manage-patch-workbench.ps1`
  - Control Center for the dedicated Patch Workbench stack.
- `upgrade.sh`
  - Pull and apply new image tags.
- `upgrade.ps1`
  - Pull and apply new image tags on Windows hosts.
- `upgrade-patch-workbench.sh` / `upgrade-patch-workbench.ps1`
  - Upgrade scripts for the dedicated Patch Workbench stack.
- `bootstrap-patch-workbench.sh` / `bootstrap-patch-workbench.ps1`
  - Raw GitHub bootstrap scripts that download only Patch Workbench installer files and min image defaults.
- `build-local-images.sh` / `build-local-images.ps1`
  - Build local backend/frontend images from this repo.
- `export-images.sh` / `export-images.ps1`
  - Export local images to a tar bundle.
- `import-images.sh` / `import-images.ps1`
  - Import image tar bundle on destination host.
- `firstboot/`
  - OVA first-boot automation files (systemd one-time setup service).
- `ova/`
  - current-version OVA stage-builder scripts and docs for a VM-based delivery path.

## Prerequisites (inside appliance VM)

- Docker Engine + Docker Compose plugin installed.
- Network route to:
  - Wazuh manager API
  - Wazuh indexer API
  - endpoint WinRM/SSH ports

## First Boot

```bash
cd /opt/click2fix/deploy/appliance
chmod +x install.sh upgrade.sh
./install.sh
```

One-click Linux launcher:

```bash
cd /opt/click2fix/deploy/appliance
chmod +x setup.sh
./setup.sh
```

Windows host:

```powershell
cd C:\click2fix\deploy\appliance
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Patch Workbench install (Linux):

```bash
cd /opt/click2fix/deploy/appliance
chmod +x install-patch-workbench.sh
./install-patch-workbench.sh
```

Patch Workbench install (Windows):

```powershell
cd C:\click2fix\deploy\appliance
powershell -ExecutionPolicy Bypass -File .\install-patch-workbench.ps1
```

Patch Workbench management/upgrade:

```bash
./manage-patch-workbench.sh
./upgrade-patch-workbench.sh
```

```powershell
.\manage-patch-workbench.ps1
.\upgrade-patch-workbench.ps1
```

One-click Windows launcher:

- Double-click `setup.cmd`

`setup.cmd` behavior:

- First run: launches first-time setup.
- Later runs: opens Control Center (start/stop/restart/status/logs/upgrade).
- Always runs installer preflight to remove download security markers and detect quarantined files.

## Windows Download Security Notes (SmartScreen/Defender)

Some endpoints mark downloaded ZIP contents as untrusted and may block or quarantine scripts.
We do not recommend disabling endpoint protection. Instead:

1. Verify the installer hash with the bundled `.sha256` file.
2. Unblock the ZIP and extracted folder before running setup.
3. If your security tool still quarantines scripts, allowlist the installer hash and the Click2Fix install directory.

Example (PowerShell):

```powershell
# Unblock the downloaded ZIP, then extract.
Unblock-File -Path .\click2fix-appliance-installer-<version>.zip
Expand-Archive -Path .\click2fix-appliance-installer-<version>.zip -DestinationPath C:\click2fix -Force

# Remove download security markers from all extracted files.
Get-ChildItem -Path C:\click2fix -Recurse -File | Unblock-File
```

If an enterprise policy enforces script restrictions, use a signed installer or request an allowlist
for the Click2Fix installer hash and `C:\click2fix` (or your chosen install path).
Raw bootstrap avoids the ZIP extraction path, but it does not replace code signing for SmartScreen reputation.

If ZIP download is blocked, bootstrap directly from GitHub raw files instead of downloading the archive:

```powershell
$version = "v1.1.4"
Invoke-WebRequest "https://raw.githubusercontent.com/helisudani0/click2fix/$version/deploy/appliance/bootstrap-from-github.ps1" -OutFile .\bootstrap-from-github.ps1
powershell -ExecutionPolicy Bypass -File .\bootstrap-from-github.ps1 -Owner helisudani0 -Repo click2fix -Version $version -InstallDir C:\Click2Fix -PullImages
```

Linux:

```bash
VERSION=v1.1.4
curl -fsSL "https://raw.githubusercontent.com/helisudani0/click2fix/${VERSION}/deploy/appliance/bootstrap-from-github.sh" -o ./bootstrap-from-github.sh
chmod +x ./bootstrap-from-github.sh
OWNER=helisudani0 REPO=click2fix VERSION=${VERSION} INSTALL_DIR=/opt/click2fix PULL_IMAGES=true ./bootstrap-from-github.sh
```

Patch Workbench bootstrap (min release tags):

```powershell
$version = "min-v1.1.4"
Invoke-WebRequest "https://raw.githubusercontent.com/helisudani0/click2fix/$version/deploy/appliance/bootstrap-patch-workbench.ps1" -OutFile .\bootstrap-patch-workbench.ps1
powershell -ExecutionPolicy Bypass -File .\bootstrap-patch-workbench.ps1 -Owner helisudani0 -Repo click2fix -Version $version -InstallDir C:\Click2Fix-PatchWorkbench -PullImages
```

```bash
VERSION=min-v1.1.4
curl -fsSL "https://raw.githubusercontent.com/helisudani0/click2fix/${VERSION}/deploy/appliance/bootstrap-patch-workbench.sh" -o ./bootstrap-patch-workbench.sh
chmod +x ./bootstrap-patch-workbench.sh
OWNER=helisudani0 REPO=click2fix VERSION=${VERSION} INSTALL_DIR=/opt/click2fix-patch-workbench PULL_IMAGES=true ./bootstrap-patch-workbench.sh
```

No backend/frontend repo workflow is needed on the customer side.

If the target environment should not have Docker installed on the analyst workstation at all, use the OVA stage-builder in:

- `deploy/appliance/ova/`

That path packages the same supported appliance runtime into a Linux VM image and keeps Docker inside the VM rather than on the customer host.

What the script does:

- creates `.env.appliance` from template if missing
- prompts only for required runtime values (Wazuh, Indexer, endpoint connector, admin, host/ports)
- prompts optional platform-wide AI settings (`C2F_AI_FEATURES_ENABLED`, `C2F_LLM_PROVIDER`, `C2F_LLM_API_KEY`)
- optionally applies static IP configuration with netplan
- updates trusted hosts and CORS for the appliance host/IP
- pulls release images automatically and starts services
- bootstraps local admin user in DB
- prints customer access URLs:
  - Frontend UI: `http://<host>:<frontend_port>`
  - Backend API docs: `http://<host>:<backend_port>/docs`
  - Backend Ops: `http://<host>:<backend_port>/ops`

If images are private in GHCR, run one-time login before setup:

```bash
docker login ghcr.io
```

Use a token with `read:packages`.

## Global Shell AI Key

For appliance installs, set the AI key in:

- `deploy/appliance/.env.appliance`

Required variables:

- `C2F_AI_FEATURES_ENABLED=true`
- `C2F_LLM_PROVIDER=openai` (or `gemini`)
- `C2F_LLM_API_KEY=<your_key>`

Then restart services from Control Center (or rerun setup) so backend/frontend reload env values.

## Test on Another System

### Option A: Online install from registry images

1. Use the release bundle or `bootstrap-from-github` script to obtain the appliance files.
2. Ensure `.env.appliance.template` or `.env.appliance` points at:
   `ghcr.io/<owner>/click2fix-backend:<version>`,
   `ghcr.io/<owner>/click2fix-frontend:<version>`,
   and `postgres:16`.
3. Run `install.sh` or `install.ps1`.
4. Script pulls images and starts stack.

### Option B: Offline/local image transfer

On source machine:

```bash
cd deploy/appliance
./build-local-images.sh
./export-images.sh ./click2fix-images.tar
```

Windows source machine:

```powershell
cd deploy\appliance
.\build-local-images.ps1
.\export-images.ps1 -OutputFile click2fix-images.tar
```

Copy `click2fix-images.tar` + `deploy/appliance` folder to destination machine.

On destination machine:

```bash
cd deploy/appliance
./import-images.sh ./click2fix-images.tar
```

Then set `C2F_SKIP_PULL=true` in `.env.appliance` (or during installer prompt) and run installer.

For later hotfixes on the same installed appliance:

- rebuild updated local images with `build-local-images.ps1` / `build-local-images.sh`, or import a new tar with `import-images.ps1` / `import-images.sh`
- keep `C2F_SKIP_PULL=true`
- run `upgrade.ps1` / `upgrade.sh` or Control Center option `7`
- the upgrade path will reuse local images and force-recreate app services instead of pulling from the registry
- set `C2F_IMAGE_RETENTION_COUNT` in `.env.appliance` (default `2`) to keep only the newest N backend/frontend/postgres images after each upgrade (`0` disables cleanup)
- set `C2F_COOKIE_SECURE=` (blank) to auto-detect per request scheme, or force `true`/`false` explicitly for strict HTTPS or HTTP-only labs

The offline/local image bundle for the current appliance includes only:

- postgres
- backend
- frontend

## Upgrade

```bash
cd /opt/click2fix/deploy/appliance
./upgrade.sh
```

Windows:

```powershell
cd C:\click2fix\deploy\appliance
.\upgrade.ps1
```

## Static IP Guidance

For stable operations, use one:

- DHCP reservation on firewall/router for appliance MAC
- static IP via first-boot wizard (netplan)

## Naming Commitment

The deployment artifacts do not hard-lock branding:

- `APP_BRAND` in `.env.appliance` can be changed later.
- image names/tags are configurable.
- VM display name and DNS can be changed without backend code changes.

## Security Notes

- Do not ship demo credentials in customer appliance.
- Keep `.env.appliance` permission-restricted (`chmod 600`).
- Rotate Wazuh/Indexer/WinRM/admin secrets per customer.

## OVA Auto-Install Behavior

If you package this as OVA, install the first-boot unit during image build:

```bash
cd /opt/click2fix/deploy/appliance/firstboot
sudo ./install-firstboot-service.sh
```

Then customer flow becomes:

1. Import OVA
2. Boot VM
3. First-boot wizard starts automatically on console
4. Enter values once
5. Appliance starts and remains persistent

Note:

- OVA/VM packaging remains a separate delivery track.
- The current `v1.1.4` supported image set remains `postgres + backend + frontend`.
- The OVA stage-builder intentionally rejects local appliance files that have drifted into the v2 bounded-service model.

## GitHub Automation

Release workflow file:

- `.github/workflows/release-appliance.yml`
- `.github/workflows/release-appliance-min.yml`
- `.github/workflows/publish-ova-asset.yml`

What it does on `v*` tag:

1. Builds backend/frontend images
2. Pushes images to GHCR
3. Builds installer bundle zip
4. Publishes release assets to GitHub Releases
5. Optionally publishes a prebuilt `.ova` + `.ova.sha256` (when provided via `workflow_dispatch` `ova_url`)

What `release-appliance-min` does on `min-v*` tag:

1. Builds backend/frontend min images (`-backend-min`, `-frontend-min`)
2. Pushes min images to GHCR
3. Builds Patch Workbench installer bundle zip
4. Publishes min release assets to GitHub Releases

Maintainer release steps:

1. Push this repository to GitHub.
2. Ensure Actions are enabled for the repo.
3. Create and push a version tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

4. Wait for workflow `release-appliance` to complete.
5. Share customer link:
   - `https://github.com/<owner>/<repo>/releases/latest`

To publish a direct-download OVA:

1. Build stage bundle:
   - `deploy/appliance/ova/build-ova-stage.sh` or `build-ova-stage.ps1`
2. Build VM image, install first-boot service, and export hypervisor VM as `.ova`.
3. Prepare OVA asset + checksum:
   - `deploy/appliance/release/add-ova-asset.sh` or `add-ova-asset.ps1`
4. Upload `.ova` and `.ova.sha256` to the matching GitHub release.
5. Optional automation path: run `release-appliance` via `workflow_dispatch` with `ova_url` pointing to the prebuilt `.ova`.

Lightweight automation path (no full image rebuild):

1. Host exported `.ova` at an HTTPS URL.
2. Run `publish-ova-asset` workflow with:
   - `version` = release tag (for example `v1.1.4`)
   - `ova_url` = URL to exported `.ova`
3. Workflow publishes `.ova` and `.ova.sha256` to the selected GitHub release tag.
