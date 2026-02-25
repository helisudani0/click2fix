$ErrorActionPreference = "Stop"

$pf86 = [Environment]::GetFolderPath("ProgramFilesX86")
if ([string]::IsNullOrWhiteSpace($pf86)) {
  $pf86 = "C:\Program Files (x86)"
}

$logFile = Join-Path $pf86 "ossec-agent\active-response\active-response.log"

function Write-Log {
  param([string]$Message)
  $line = "{0} patch-windows: {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
  Add-Content -Path $logFile -Value $line
}

try {
  Write-Log "Started"
  $usoClient = Join-Path $env:SystemRoot "System32\UsoClient.exe"
  if (Test-Path $usoClient) {
    & $usoClient StartScan
    Start-Sleep -Seconds 3
    & $usoClient StartDownload
    Start-Sleep -Seconds 3
    & $usoClient StartInstall
    Write-Log "Triggered update scan/download/install via UsoClient"
  }
  else {
    $wuauclt = Join-Path $env:SystemRoot "System32\wuauclt.exe"
    if (Test-Path $wuauclt) {
      & $wuauclt /detectnow
      Write-Log "Triggered update detection via wuauclt fallback"
    }
    else {
      Write-Log "No update client found (UsoClient/wuauclt missing)"
      exit 1
    }
  }

  Write-Log "Completed successfully"
  exit 0
}
catch {
  Write-Log ("Failed: " + $_.Exception.Message)
  exit 1
}
