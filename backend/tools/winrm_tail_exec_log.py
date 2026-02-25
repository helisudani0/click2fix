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
    ap = argparse.ArgumentParser(description="Tail Click2Fix endpoint executions log via WinRM.")
    ap.add_argument("--ip", required=True)
    ap.add_argument("--agent-id", required=True, help="Used for env-var lookup: C2F_WINRM_USERNAME_<agent>")
    ap.add_argument("--exec-id", required=True, help="Execution id to filter for (exec=<id>).")
    ap.add_argument("--tail", type=int, default=600, help="How many log lines to tail before filtering.")
    ap.add_argument("--limit", type=int, default=160, help="How many matching lines to print.")
    ap.add_argument(
        "--proc-regex",
        default=r"winget\.exe|msiexec\.exe|docker|virtualbox|vbox|installer",
        help="Regex applied to process Name/CommandLine when listing/killing.",
    )
    ap.add_argument("--list-procs", action="store_true", help="List matching processes after tailing log.")
    ap.add_argument(
        "--kill-procs",
        action="store_true",
        help="Kill matching processes (dangerous). Implies --list-procs.",
    )
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

    # Keep the remote command small and PowerShell 5.1 compatible.
    exec_id = str(args.exec_id).strip()
    needle = f" exec={exec_id} "
    needle_ps = needle.replace("'", "''")
    tail = max(50, int(args.tail))
    limit = max(10, int(args.limit))
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$ProgressPreference='SilentlyContinue';"
        "$lf='C:\\Click2Fix\\logs\\executions.log';"
        f"$needle='{needle_ps}';"
        f"$tail={tail};"
        f"$limit={limit};"
        "if(Test-Path $lf){"
        "Get-Content -Path $lf -Tail $tail | "
        "Select-String -SimpleMatch $needle | "
        "Select-Object -Last $limit | "
        "ForEach-Object { $_.Line }"
        "} else {"
        "Write-Output ('missing_log_file='+$lf)"
        "}"
    )
    res = session.run_ps(ps)
    out = (res.std_out or b"").decode(errors="replace")
    err = (res.std_err or b"").decode(errors="replace")

    if out.strip():
        print(out.rstrip())
    if err.strip():
        print(err.rstrip(), file=sys.stderr)

    if args.kill_procs:
        args.list_procs = True

    if args.list_procs:
        re_text = str(args.proc_regex or "").strip()
        re_ps = re_text.replace("'", "''")
        kill_ps = "$kill=$false;"
        if args.kill_procs:
            kill_ps = "$kill=$true;"
        proc_ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$ProgressPreference='SilentlyContinue';"
            f"$re='{re_ps}';"
            + kill_ps
            + "$procs=Get-CimInstance Win32_Process | "
            "Where-Object { $_.Name -match $re -or (($_.CommandLine) -and ($_.CommandLine -match $re)) };"
            "if(-not $procs){ Write-Output 'no_matching_processes'; exit 0 };"
            "foreach($p in $procs){"
            "$start='';"
            "try{ $start=[Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate).ToString('o') }catch{};"
            "Write-Output ('proc='+$p.Name+' pid='+$p.ProcessId+' start='+$start+' cmd='+($p.CommandLine -replace \"`r|`n\",' '));"
            "if($kill){ try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Write-Output ('killed='+$p.ProcessId) }catch{ Write-Output ('kill_failed='+$p.ProcessId+' err='+$_.Exception.Message) } }"
            "}"
        )
        proc_res = session.run_ps(proc_ps)
        proc_out = (proc_res.std_out or b"").decode(errors="replace").strip()
        proc_err = (proc_res.std_err or b"").decode(errors="replace").strip()
        if proc_out:
            print("\n--- process_diag ---")
            print(proc_out)
        if proc_err:
            print(proc_err, file=sys.stderr)

    return int(res.status_code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
