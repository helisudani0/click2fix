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
    ap = argparse.ArgumentParser(description="Force-stop Click2Fix package-update activity on a Windows agent via WinRM.")
    ap.add_argument("--ip", required=True)
    ap.add_argument("--agent-id", required=True)
    ap.add_argument(
        "--delay-seconds",
        type=int,
        default=3,
        help="Delay before killing WinRM provider hosts (so this WinRM command can return).",
    )
    ap.add_argument(
        "--kill-winrm-host",
        action="store_true",
        help="Also kill wsmprovhost.exe processes (terminates running WinRM shells).",
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

    delay = max(1, int(args.delay_seconds))
    kill_winrm = bool(args.kill_winrm_host)

    # Kill winget + any WinGet temp installers currently running. This releases the global winget mutex.
    # Optionally, also kill wsmprovhost (WinRM plugin hosts) to terminate any stuck remote shells.
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$ProgressPreference='SilentlyContinue';"
        "$killed=@();"
        # Kill WinGet temp installers first.
        "$procs=Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and ($_.CommandLine -match '\\\\AppData\\\\Local\\\\Temp\\\\WinGet\\\\') };"
        "foreach($p in $procs){"
        "try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $killed += ('killed_pid='+$p.ProcessId+' name='+$p.Name) }catch{ $killed += ('kill_failed_pid='+$p.ProcessId+' err='+$_.Exception.Message) }"
        "}"
        # Kill winget itself (and its service helper if present).
        "foreach($n in @('winget.exe','WindowsPackageManagerServer.exe','AppInstallerCLI.exe')){"
        "$ps2=Get-CimInstance Win32_Process -Filter (\"Name='\"+$n+\"'\");"
        "foreach($p in $ps2){"
        "try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $killed += ('killed_pid='+$p.ProcessId+' name='+$p.Name) }catch{ $killed += ('kill_failed_pid='+$p.ProcessId+' err='+$_.Exception.Message) }"
        "}"
        "}"
        "Write-Output ('killed_count='+$killed.Count);"
        "foreach($line in $killed){ Write-Output $line };"
    )
    res = session.run_ps(ps)
    out = (res.std_out or b"").decode(errors="replace").strip()
    err = (res.std_err or b"").decode(errors="replace").strip()

    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)

    if kill_winrm:
        # Spawn a detached kill so we don't kill the current host before returning.
        ps2 = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$ProgressPreference='SilentlyContinue';"
            f"$d={delay};"
            # /T kills child processes; /F forces.
            "$cmd=('/c timeout /t '+$d+' /nobreak >NUL & taskkill /F /IM wsmprovhost.exe /T >NUL 2>&1');"
            "Start-Process -FilePath cmd.exe -ArgumentList $cmd -WindowStyle Hidden | Out-Null;"
            "Write-Output ('scheduled_taskkill_wsmprovhost_after_seconds='+$d)"
        )
        res2 = session.run_ps(ps2)
        out2 = (res2.std_out or b"").decode(errors="replace").strip()
        err2 = (res2.std_err or b"").decode(errors="replace").strip()
        if out2:
            print(out2)
        if err2:
            print(err2, file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

