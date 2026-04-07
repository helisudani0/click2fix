# OVA Stage Builder

This folder provides the current-version VM packaging path for Click2Fix.

Goal:

- ship `v1.1.4` as a VM appliance without requiring Docker on the customer workstation
- avoid ZIP-heavy installer flows on endpoints where Windows security policies quarantine extracted scripts
- keep the runtime aligned to the supported appliance image set:
  - `postgres:16`
  - `ghcr.io/<owner>/click2fix-backend:<tag>`
  - `ghcr.io/<owner>/click2fix-frontend:<tag>`

What this is:

- a staging-bundle builder for OVA packaging
- a maintainer-oriented path for importing the current appliance files into a Linux VM image
- a packaging workflow that reuses the existing `deploy/appliance/firstboot/` service

What this is not:

- a second non-Docker runtime
- a signed Windows installer
- a v2 bounded-services appliance

## Build The OVA Stage Bundle

Linux:

```bash
cd deploy/appliance/ova
chmod +x build-ova-stage.sh
./build-ova-stage.sh v1.1.4 helisudani0
```

Windows:

```powershell
cd deploy\appliance\ova
.\build-ova-stage.ps1 -Version v1.1.4 -Owner helisudani0
```

Output:

- `deploy/releases/v1.1.4/click2fix-appliance-ova-stage-v1.1.4/`

The output contains:

- `opt/click2fix/deploy/appliance/...`
- the existing first-boot unit files
- an `OVA_STAGE_README.txt` with the exact VM-side install path

If you run the builder from this Git checkout, it prefers the committed `HEAD` appliance files.
That prevents local uncommitted v2 experiments from leaking into the current OVA stage bundle.

## Turn The Stage Bundle Into An OVA

Recommended maintainer flow:

1. Create a clean Ubuntu Server LTS VM.
2. Install Docker Engine and the Docker Compose plugin inside the VM.
3. Copy the staged `opt/` tree into the VM root filesystem.
4. Run:

```bash
cd /opt/click2fix/deploy/appliance/firstboot
sudo ./install-firstboot-service.sh
```

5. Power off the VM.
6. Export the VM as an OVA from VirtualBox, VMware, or your preferred hypervisor.

Customer flow after import:

1. Import OVA.
2. Boot VM.
3. First-boot installer launches automatically.
4. Enter Wazuh, indexer, connector, and admin values.
5. Use Click2Fix normally without installing Docker on the customer host.

## Publish OVA For Customer Download

After exporting your VM as `.ova`, prepare and publish release assets:

1. Prepare OVA + checksum files in the release output tree.
2. Upload both files to GitHub Releases under the matching tag.

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

Release workflow support:

- `.github/workflows/release-appliance.yml` now supports optional `workflow_dispatch` input `ova_url`.
- If `ova_url` is provided, the workflow downloads `click2fix-appliance-<version>.ova`, generates `.ova.sha256`, and publishes both as release assets.
- `.github/workflows/publish-ova-asset.yml` provides a lightweight OVA-only publish path for existing release tags.

## Guardrails

The stage-builder scripts intentionally fail if the local appliance scaffold has drifted into the v2 service model.

That means they will reject:

- `agent-manager`
- `event-indexer`
- `alert-service`
- `case-service`
- `ingest-gateway`
- `soar-service`
- `detection-service`

This is deliberate. The current appliance release path must remain scoped to the `v1.1.4` image set.
