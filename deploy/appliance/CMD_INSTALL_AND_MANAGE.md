# Click2Fix Windows CMD-Only Guide (No ZIP, No PowerShell)

This guide is for environments where `.zip` extraction and/or `.ps1` execution are blocked.
All commands below run from `cmd.exe`.

## 1) Prerequisites

```cmd
docker --version
docker compose version
docker info
```

If `docker info` fails, start Docker Desktop first.

## 2) Download Appliance Runtime Files

```cmd
set C2F_VERSION=v1.1.5
mkdir C:\Click2Fix
cd /d C:\Click2Fix
curl -fL -o docker-compose.yml https://raw.githubusercontent.com/helisudani0/click2fix/%C2F_VERSION%/deploy/appliance/docker-compose.appliance.yml
curl -fL -o .env.appliance.template https://raw.githubusercontent.com/helisudani0/click2fix/%C2F_VERSION%/deploy/appliance/.env.appliance.template
curl -fL -o nginx.conf https://raw.githubusercontent.com/helisudani0/click2fix/%C2F_VERSION%/deploy/appliance/nginx.conf
copy /Y .env.appliance.template .env.appliance
```

## 3) Configure Environment

```cmd
notepad .env.appliance
```

Set these values at minimum:

```env
C2F_BACKEND_IMAGE=ghcr.io/helisudani0/click2fix-backend
C2F_FRONTEND_IMAGE=ghcr.io/helisudani0/click2fix-frontend
C2F_IMAGE_TAG=1.1.5
COMPOSE_PROJECT_NAME=click2fix
POSTGRES_PASSWORD=<strong-db-password>
JWT_SECRET=<long-random-secret>
WAZUH_URL=https://<wazuh-host>:55000
WAZUH_USER=<wazuh-user>
WAZUH_PASSWORD=<wazuh-password>
INDEXER_URL=https://<indexer-host>:9200
INDEXER_USER=<indexer-user>
INDEXER_PASSWORD=<indexer-password>
C2F_BOOTSTRAP_ADMIN_USERNAME=admin
C2F_BOOTSTRAP_ADMIN_PASSWORD=<strong-admin-password>
VITE_TENANT_GOVERNANCE_ENABLED=false
```

Important:

- Use `C2F_IMAGE_TAG=1.1.5` (not `v1.1.5`).
- Do not use `latest` for appliance installs; pin a numbered release tag so backend/frontend stay in lockstep.
- Keep using `--env-file .env.appliance` in every `docker compose` command.

## 4) Optional GHCR Login (Private Packages Only)

```cmd
set GHCR_USER=<github-username>
set GHCR_PAT=<github-pat-with-read:packages>
echo %GHCR_PAT%| docker login ghcr.io -u %GHCR_USER% --password-stdin
set GHCR_PAT=
```

## 5) Pull and Start Stack

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml pull
docker compose --env-file .env.appliance -f docker-compose.yml up -d --remove-orphans
docker compose --env-file .env.appliance -f docker-compose.yml ps
```

## 6) Bootstrap Admin User (Installer-Equivalent Step)

Run this once after backend is healthy, or again any time you need to reset admin credentials:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml exec -T -w /app backend python -m tools.bootstrap_admin --username admin --password <strong-admin-password> --role admin
```

## 7) Access URLs

- Frontend UI: `http://localhost:5173`
- Backend API docs: `http://localhost:8000/docs`
- Backend ops: `http://localhost:8000/ops`

If you changed ports in `.env.appliance`, use those instead.

## 8) Control Center Equivalents (CMD)

Start:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml up -d --remove-orphans
```

Stop:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml stop
```

Restart:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml restart
```

Status:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml ps
```

Tail backend logs:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml logs -f backend
```

Tail load balancer logs:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml logs -f c2f-lb
```

## 9) Upgrade to a New Image Tag

1) Edit tag in `.env.appliance`:

```cmd
notepad .env.appliance
```

Set:

```env
C2F_IMAGE_TAG=<new-tag>
```

2) Pull and recreate app services:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml pull
docker compose --env-file .env.appliance -f docker-compose.yml up -d --remove-orphans --force-recreate backend frontend
docker compose --env-file .env.appliance -f docker-compose.yml ps
```

## 10) Troubleshooting

`pull access denied for click2fix-backend:local`

- `.env.appliance` still has defaults.
- Fix `C2F_BACKEND_IMAGE`, `C2F_FRONTEND_IMAGE`, and `C2F_IMAGE_TAG`.

`POSTGRES_PASSWORD is required`

- You ran compose without env-file.
- Use:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml <command>
```

`c2f-lb` restarting with `no "events" section in configuration`

- Local `nginx.conf` is wrong/corrupted.
- Re-download and recreate only `c2f-lb`:

```cmd
curl -fL -o nginx.conf https://raw.githubusercontent.com/helisudani0/click2fix/v1.1.5/deploy/appliance/nginx.conf
docker compose --env-file .env.appliance -f docker-compose.yml up -d --force-recreate c2f-lb
docker compose --env-file .env.appliance -f docker-compose.yml logs --tail 80 c2f-lb
```

`Invoke-WebRequest` or `$version` not recognized

- You are in `cmd.exe`, not PowerShell.
- Use the CMD commands in this guide (`curl`, `set`, `docker compose ...`).

Container name like `click2fixtest-backend-1`

- Normal compose naming: `<project>-<service>-<replica>`.
- Set stable project name with:

```env
COMPOSE_PROJECT_NAME=click2fix
```
