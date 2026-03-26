# OVA Build Blueprint

This project now includes appliance runtime files, and the current repo also includes OVA stage-builder scripts under:

- `deploy/appliance/ova/build-ova-stage.ps1`
- `deploy/appliance/ova/build-ova-stage.sh`

Those scripts generate the staged appliance tree that should be copied into the VM image before export.

Recommended toolchain:

- Packer (to build VM image)
- VirtualBox or VMware builder
- Ubuntu Server LTS base image

## Build Stages

1. Provision base VM image with:
   - Docker Engine
   - Docker Compose plugin
   - Git (optional)
   - netplan (default on Ubuntu)
2. Copy appliance files into VM:
   - use the generated output from `deploy/releases/<version>/click2fix-appliance-ova-stage-<version>/opt/click2fix/deploy/appliance`
3. Install first-boot systemd unit:
   - `cd /opt/click2fix/deploy/appliance/firstboot`
   - `sudo ./install-firstboot-service.sh`
4. Power off and export to OVA.

## Notes

- OVA build pipeline is intentionally separate from app runtime code.
- Keep customer secrets out of OVA template. First-boot wizard collects them.
- Current release scope is still the `postgres + backend + frontend` appliance image set.
- Do not include `agent-manager`, `event-indexer`, or other v2 bounded services in the current OVA delivery path.
