# Click2Fix Appliance Deployment (OVA-Oriented)

This folder is the customer-facing deployment scaffold for a VM appliance model.

The intended flow:

1. Customer imports OVA VM.
2. Customer runs first-boot wizard (`install.sh`) inside VM.
3. Customer enters only operational values (Wazuh/Indexer/connector/admin credentials).
4. Services start automatically with Docker Compose.

## Direct Customer Download (GitHub Releases)

Once a release tag is published (for example `v1.2.0`), customers can download directly from:

- `https://github.com/<owner>/<repo>/releases/latest`
- or pinned release:
  - `https://github.com/<owner>/<repo>/releases/tag/v1.2.0`

Download asset:

- `click2fix-appliance-installer-v1.2.0.zip` (name varies by release tag)

## Files

- `docker-compose.appliance.yml`
  - Image-based runtime (no source code mounts, no local dev workflow).
- `.env.appliance.template`
  - Customer config template with placeholders.
- `install.sh`
  - Interactive first-boot setup and launch script.
- `install.ps1`
  - Interactive first-boot setup and launch script for Windows hosts.
- `setup.sh` / `setup.cmd`
  - One-click launcher wrappers for installers.
- `manage.sh` / `manage.cmd` / `manage.ps1`
  - Control Center (start/stop/restart/status/logs/upgrade/show access URLs).
- `upgrade.sh`
  - Pull and apply new image tags.
- `upgrade.ps1`
  - Pull and apply new image tags on Windows hosts.
- `build-local-images.sh` / `build-local-images.ps1`
  - Build local backend/frontend images from this repo.
- `export-images.sh` / `export-images.ps1`
  - Export local images to a tar bundle.
- `import-images.sh` / `import-images.ps1`
  - Import image tar bundle on destination host.
- `firstboot/`
  - OVA first-boot automation files (systemd one-time setup service).

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

No backend/frontend repo workflow is needed on the customer side.

What the script does:

- creates `.env.appliance` from template if missing
- prompts only for required runtime values (Wazuh, Indexer, endpoint connector, admin, host/ports)
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

## Test on Another System

### Option A: Online install from registry images

1. Set image repo/tag values in `.env.appliance`.
2. Run `install.sh` or `install.ps1`.
3. Script pulls images and starts stack.

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

## GitHub Automation

Release workflow file:

- `.github/workflows/release-appliance.yml`

What it does on `v*` tag:

1. Builds backend/frontend images
2. Pushes images to GHCR
3. Builds installer bundle zip
4. Publishes release assets to GitHub Releases

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
