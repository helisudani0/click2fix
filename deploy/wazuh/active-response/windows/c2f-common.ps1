# Force UTF-8 encoding to prevent corrupted log characters
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$script:Pf86 = [Environment]::GetFolderPath("ProgramFilesX86")
if ([string]::IsNullOrWhiteSpace($script:Pf86)) {
  $script:Pf86 = "C:\Program Files (x86)"
}

$script:BaseDir = Join-Path $script:Pf86 "ossec-agent\active-response"
$script:LogFile = Join-Path $script:BaseDir "active-response.log"
$script:OutputDir = Join-Path $script:BaseDir "output"
$script:QuarantineDir = Join-Path $script:BaseDir "quarantine"
$script:BlocklistFile = Join-Path $script:BaseDir "ioc-blocklist.txt"
$script:ReportsDir = Join-Path $script:BaseDir "reports"

foreach ($path in @($script:BaseDir, $script:OutputDir, $script:QuarantineDir, $script:ReportsDir)) {
  if (-not (Test-Path $path)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }
}
if (-not (Test-Path $script:LogFile)) {
  New-Item -ItemType File -Path $script:LogFile -Force | Out-Null
}

function Write-C2FLog {
  param(
    [Parameter(Mandatory = $true)][string]$Action,
    [Parameter(Mandatory = $true)][string]$Message
  )
  $line = "{0} {1}: {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Action, $Message
  Add-Content -Path $script:LogFile -Value $line
}

function Get-C2FInputArgs {
  param([string[]]$CliArgs)

  $values = New-Object System.Collections.Generic.List[string]
  if ($CliArgs) {
    foreach ($arg in $CliArgs) {
      if ($null -ne $arg -and -not [string]::IsNullOrWhiteSpace("$arg")) {
        $values.Add("$arg")
      }
    }
  }

  try {
    if ([Console]::IsInputRedirected) {
      $raw = [Console]::In.ReadToEnd()
      if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $json = $raw | ConvertFrom-Json -Depth 25
        $extra = $json.parameters.extra_args
        if ($extra) {
          foreach ($item in $extra) {
            if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace("$item")) {
              $values.Add("$item")
            }
          }
        }
      }
    }
  }
  catch {
    # Ignore stdin parse errors and continue with CLI args only.
  }

  return $values.ToArray()
}

function Get-C2FArg {
  param(
    [string[]]$Args,
    [int]$Index,
    [string]$Name
  )
  if (-not $Args -or $Args.Count -le $Index -or [string]::IsNullOrWhiteSpace("$($Args[$Index])")) {
    throw "Missing required argument: $Name"
  }
  return "$($Args[$Index])"
}

function Test-C2FIpAddress {
  param([string]$Ip)
  return [bool]($Ip -match '^(?:\d{1,3}\.){3}\d{1,3}$')
}

function Save-C2FReport {
  param(
    [string]$Action,
    [object]$Payload,
    [string]$Extension = "json"
  )

  $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $filePath = Join-Path $script:OutputDir ("{0}_{1}.{2}" -f $Action, $timestamp, $Extension)

  if ($Extension -eq "json") {
    $Payload | ConvertTo-Json -Depth 20 | Set-Content -Path $filePath -Encoding UTF8
  }
  else {
    "$Payload" | Set-Content -Path $filePath -Encoding UTF8
  }

  return $filePath
}

function Get-C2FServiceName {
  param([string[]]$Names)
  foreach ($name in $Names) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {
      return $name
    }
  }
  return $null
}

function Normalize-C2FKb {
  param([string]$Input)
  if ([string]::IsNullOrWhiteSpace($Input)) { return $null }
  $kb = $Input.ToUpperInvariant().Trim()
  if ($kb.StartsWith("KB")) {
    $kb = $kb.Substring(2)
  }
  if ($kb -match '^\d+$') {
    return $kb
  }
  return $null
}

function Find-C2FYaraExe {
  $candidates = @(
    (Join-Path $PSScriptRoot "yara64.exe"),
    (Join-Path $PSScriptRoot "yara.exe"),
    "C:\Program Files\YARA\yara64.exe",
    "C:\Program Files\YARA\yara.exe"
  )
  foreach ($candidate in $candidates) {
    if (Test-Path $candidate) {
      return $candidate
    }
  }
  return $null
}

function Upload-C2FReport {
  param(
    [string]$FilePath,
    [string]$ExecutionId,
    [string]$ActionName,
    [string]$ApiUrl = "http://localhost:8000",
    [int]$TimeoutSeconds = 30
  )

  if ([string]::IsNullOrWhiteSpace($FilePath) -or -not (Test-Path $FilePath)) {
    Write-C2FLog -Action "upload-report" -Message "Report file not found: $FilePath"
    return $false
  }

  try {
    $fileContent = Get-Content -Path $FilePath -Raw -ErrorAction Stop
    $fileName = Split-Path -Leaf $FilePath
    $endpoint = "$ApiUrl/api/forensics/reports"
    
    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    
    $boundary = [guid]::NewGuid().ToString()
    $body = [System.Text.Encoding]::UTF8.GetBytes(
      "--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$fileName`"`r`nContent-Type: application/json`r`n`r`n"
    ) + $fileBytes + [System.Text.Encoding]::UTF8.GetBytes(
      "`r`n--$boundary`r`nContent-Disposition: form-data; name=`"execution_id`"`r`n`r`n$ExecutionId`r`n" +
      "--$boundary`r`nContent-Disposition: form-data; name=`"action`"`r`n`r`n$ActionName`r`n--$boundary--`r`n"
    )

    $client = New-Object System.Net.WebClient
    $client.Headers.Add("Content-Type", "multipart/form-data; boundary=$boundary")
    
    $result = $client.UploadData($endpoint, $body)
    Write-C2FLog -Action "upload-report" -Message "Report uploaded: $fileName to $endpoint"
    return $true
  }
  catch {
    Write-C2FLog -Action "upload-report" -Message "Failed to upload report: $($_.Exception.Message)"
    return $false
  }
}

