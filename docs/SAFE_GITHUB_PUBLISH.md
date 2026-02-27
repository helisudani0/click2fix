# Safe GitHub Publish Checklist

Use this checklist to avoid pushing local secrets or runtime artifacts.

## 1. Confirm local secret files are ignored

These should stay local and must not be committed:

- `backend/.env`
- `docker/.env`
- `deploy/appliance/.env.appliance`

Root `.gitignore` already ignores them.

## 2. Initialize repo (if not initialized yet)

```bash
git init
git branch -M main
```

## 3. Stage files

Preferred:

```bash
git add .
```

Because `.gitignore` is now present, secret `.env` files and generated artifacts should not be staged.

## 4. Verify staged files are safe

```bash
git status --short
```

Check that none of these are staged:

- `backend/.env`
- `docker/.env`
- `deploy/appliance/.env.appliance`
- `backend/data/*`
- `frontend/node_modules/*`
- `frontend/dist/*`

If any appear, unstage:

```bash
git restore --staged <path>
```

## 5. Run a secret scan before commit

PowerShell (works without `rg`):

```powershell
git diff --cached | Select-String -Pattern 'WAZUH_PASSWORD=','INDEXER_PASSWORD=','JWT_SECRET=','C2F_WINRM_PASSWORD=' -CaseSensitive
```

Optional (`rg` installed):

```powershell
rg -n --hidden -S "WAZUH_PASSWORD=|INDEXER_PASSWORD=|JWT_SECRET=|C2F_WINRM_PASSWORD=" backend docker deploy .github README.md docs -g "!**/node_modules/**" -g "!**/dist/**" -g "!backend/.env" -g "!docker/.env"
```

Expected output: no matches with real credentials.

## 6. Commit and push

```bash
git commit -m "Add appliance installer and GitHub release pipeline"
git remote add origin https://github.com/<owner>/<repo>.git
git push -u origin main
```

## 7. Publish release tag (example: v1.1.0)

```bash
git tag v1.1.0
git push origin v1.1.0
```

Then share:

- `https://github.com/<owner>/<repo>/releases/latest`
