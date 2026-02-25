# Appliance Release Packaging

Use these scripts to generate a customer-downloadable installer bundle from this repo.

## Local Packaging

Linux:

```bash
cd deploy/appliance/release
chmod +x build-installer-bundle.sh
./build-installer-bundle.sh v1.0.0 your-github-id
```

Windows:

```powershell
cd deploy\appliance\release
.\build-installer-bundle.ps1 -Version v1.0.0 -Owner your-github-id
```

Output:

- `deploy/releases/v1.0.0/click2fix-appliance-installer-v1.0.0.zip`
- `deploy/releases/v1.0.0/click2fix-appliance-installer-v1.0.0.sha256`

The generated template is pre-filled with:

- `C2F_BACKEND_IMAGE=ghcr.io/<owner>/click2fix-backend`
- `C2F_FRONTEND_IMAGE=ghcr.io/<owner>/click2fix-frontend`
- `C2F_IMAGE_TAG=<version without v>`
- `C2F_SKIP_PULL=false`
