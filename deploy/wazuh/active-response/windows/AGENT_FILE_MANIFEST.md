# Windows Agent File Manifest (Click2Fix)

Target path on agent:

- `C:\Program Files (x86)\ossec-agent\active-response\bin\`

## Already in repo

- `c2f-runner.cmd`
- `c2f-runner.ps1`
- `restart-wazuh.cmd`
- `restart-wazuh.ps1`
- `patch-windows.cmd`
- `patch-windows.ps1`
- `firewall-drop.cmd`
- `firewall-drop.ps1`
- `host-deny.cmd`
- `host-deny.ps1`
- `win_route-null.cmd`
- `win_route-null.ps1`
- `kill-process.cmd`
- `kill-process.ps1`
- `quarantine-file.cmd`
- `quarantine-file.ps1`
- `malware-scan.cmd`
- `malware-scan.ps1`
- `sca-rescan.cmd`
- `sca-rescan.ps1`
- `patch-linux.cmd`
- `patch-linux.ps1`
- `collect-forensics.cmd`
- `collect-forensics.ps1`
- `route-null.cmd`
- `route-null.ps1`
- `netsh.cmd`
- `netsh.ps1`
- `disable-account.cmd`
- `disable-account.ps1`
- `ioc-scan.cmd`
- `ioc-scan.ps1`
- `yara-scan.cmd`
- `yara-scan.ps1`
- `collect-memory.cmd`
- `collect-memory.ps1`
- `hash-blocklist.cmd`
- `hash-blocklist.ps1`
- `service-restart.cmd`
- `service-restart.ps1`
- `threat-hunt-persistence.cmd`
- `threat-hunt-persistence.ps1`
- `rollback-kb.cmd`
- `rollback-kb.ps1`
- `c2f-common.ps1`
- `c2f-actions.ps1`
- `rules\\default.yar`

## Minimum files required for single-runner mode

If backend uses `active_response.runner.command: c2f-runner`, these are the only required agent files:

- `c2f-runner.cmd`
- `c2f-runner.ps1`
- `c2f-common.ps1`
- `c2f-actions.ps1`
- `rules\\default.yar` (required only for `yara-scan`)

## Agent-side account and privilege requirements

If Wazuh Agent service runs as a domain account, that account needs:

- Local `Administrators` membership on the endpoint.
- `Log on as a service` right.
- Permission to restart services (`restart-wazuh`, `service-restart`, `sca-rescan`).
- Permission to manage firewall and routes (`firewall-drop`, `host-deny`, `netsh`, `route-null`, `win_route-null`).
- Permission to manage local users (`disable-account`).
- Permission to write under:
  - `C:\\Program Files (x86)\\ossec-agent\\active-response\\`
- Defender access for `malware-scan` cmdlets (`Start-MpScan`).
- Extra privilege for full memory dump (`collect-memory`):
  - `SeDebugPrivilege` (or run agent as `LocalSystem`).

Notes:

- Keep command names in manager config exactly the same as backend settings command values.
- `patch-linux` exists as a Windows stub and returns unsupported by design.
