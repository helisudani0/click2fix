import argparse
import os
import sys


def _creds(agent_id: str) -> tuple[str, str]:
    agent_id = (agent_id or "").strip()
    user = os.getenv(f"C2F_WINRM_USERNAME_{agent_id}") if agent_id else None
    pwd = os.getenv(f"C2F_WINRM_PASSWORD_{agent_id}") if agent_id else None
    user = user or os.getenv("C2F_WINRM_USERNAME") or ""
    pwd = pwd or os.getenv("C2F_WINRM_PASSWORD") or ""
    return user, pwd


def main() -> int:
    ap = argparse.ArgumentParser(description="Search Click2Fix endpoint executions log via WinRM.")
    ap.add_argument("--ip", required=True)
    ap.add_argument("--agent-id", required=True)
    ap.add_argument("--pattern", required=True, help="SimpleMatch search string.")
    ap.add_argument("--tail", type=int, default=20000)
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()

    try:
        import winrm  # type: ignore
    except Exception as exc:
        print(f"pywinrm import failed: {exc}", file=sys.stderr)
        return 2

    user, pwd = _creds(args.agent_id)
    if not user or not pwd:
        print("Missing WinRM credentials in env vars.", file=sys.stderr)
        return 2

    endpoint = f"http://{args.ip}:5985/wsman"
    session = winrm.Session(
        endpoint,
        auth=(user, pwd),
        transport="ntlm",
        server_cert_validation="ignore",
        operation_timeout_sec=30,
        read_timeout_sec=90,
    )

    pattern = str(args.pattern or "").strip()
    pattern_ps = pattern.replace("'", "''")
    tail = max(200, int(args.tail))
    limit = max(10, int(args.limit))
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$ProgressPreference='SilentlyContinue';"
        "$lf='C:\\Click2Fix\\logs\\executions.log';"
        f"$pat='{pattern_ps}';"
        f"$tail={tail};"
        f"$limit={limit};"
        "if(Test-Path $lf){"
        "Get-Content -Path $lf -Tail $tail | "
        "Select-String -SimpleMatch $pat | "
        "Select-Object -Last $limit | "
        "ForEach-Object { $_.Line }"
        "} else {"
        "Write-Output ('missing_log_file='+$lf)"
        "}"
    )
    res = session.run_ps(ps)
    out = (res.std_out or b"").decode(errors="replace").strip()
    err = (res.std_err or b"").decode(errors="replace").strip()

    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return int(res.status_code or 0)


if __name__ == "__main__":
    raise SystemExit(main())

