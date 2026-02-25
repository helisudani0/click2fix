# OVA Build Blueprint

This project now includes appliance runtime files, but OVA image building requires a VM image pipeline.

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
   - `deploy/appliance/docker-compose.appliance.yml`
   - `deploy/appliance/.env.appliance.template`
   - `deploy/appliance/install.sh`
   - `deploy/appliance/setup.sh`
   - `deploy/appliance/upgrade.sh`
   - `deploy/appliance/firstboot/c2f-firstboot.sh`
   - `deploy/appliance/firstboot/c2f-firstboot.service`
   - `deploy/appliance/firstboot/install-firstboot-service.sh`
   - `backend/tools/bootstrap_admin.py`
3. Install first-boot systemd unit:
   - `cd /opt/click2fix/deploy/appliance/firstboot`
   - `sudo ./install-firstboot-service.sh`
4. Power off and export to OVA.

## Notes

- OVA build pipeline is intentionally separate from app runtime code.
- Keep customer secrets out of OVA template. First-boot wizard collects them.
