# Appliance Release Packaging

Use these scripts to generate a customer-downloadable installer bundle from this repo.

Current `v1.1.4` release scope:

- appliance runtime: `postgres`, `backend`, `frontend`
- published Click2Fix images: backend + frontend only
- v2 bounded services are not part of the current appliance release bundle

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

## Add A Prebuilt OVA Release Asset

After you export a VM as `.ova`, prepare release-ready OVA assets:

Linux:

```bash
cd deploy/appliance/release
chmod +x add-ova-asset.sh
./add-ova-asset.sh v1.1.4 /path/to/click2fix-appliance-v1.1.4.ova
```

Windows:

```powershell
cd deploy\appliance\release
.\add-ova-asset.ps1 -Version v1.1.4 -SourceOvaPath C:\path\click2fix-appliance-v1.1.4.ova
```

Output:

- `deploy/releases/v1.1.4/click2fix-appliance-v1.1.4.ova`
- `deploy/releases/v1.1.4/click2fix-appliance-v1.1.4.ova.sha256`

Then upload both files to the matching GitHub release so customers can directly import the OVA into VirtualBox/VMware.

If you want GitHub Actions to publish them automatically for an existing tag:

- run `.github/workflows/publish-ova-asset.yml`
- set `version` and `ova_url`
- workflow uploads `.ova` and `.ova.sha256` to that release

The generated template is pre-filled with:

- `C2F_BACKEND_IMAGE=ghcr.io/<owner>/click2fix-backend`
- `C2F_FRONTEND_IMAGE=ghcr.io/<owner>/click2fix-frontend`
- `C2F_IMAGE_TAG=<version without v>`
- `C2F_SKIP_PULL=false`

AI assistant is optional and configured by customer in `.env.appliance`:

- `C2F_AI_FEATURES_ENABLED=true`
- `C2F_LLM_PROVIDER=openai` (or `gemini`)
- `C2F_LLM_API_KEY=<key>`

If ZIP delivery is blocked on the target environment, use the raw-file bootstrap path documented in:

- `deploy/appliance/bootstrap-from-github.ps1`
- `deploy/appliance/bootstrap-from-github.sh`

If the target environment should not install Docker on the analyst workstation, use the VM packaging path documented in:

- `deploy/appliance/ova/README.md`

Build the OVA stage bundle with:

- `deploy/appliance/ova/build-ova-stage.ps1`
- `deploy/appliance/ova/build-ova-stage.sh`

The release bundle and the OVA stage-builder both fail fast if the local appliance scaffold contains v2-only services. That is intentional so the current release line does not silently ship the wrong runtime model.
When they are run from this Git checkout, they prefer the committed `HEAD` appliance files so local uncommitted v2 changes do not contaminate a `v1.1.4` package.
