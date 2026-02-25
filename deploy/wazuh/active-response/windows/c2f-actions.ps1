. "$PSScriptRoot\c2f-common.ps1"

function Invoke-C2FAction {
  param(
    [Parameter(Mandatory = $true)][string]$ActionName,
    [string[]]$CliArgs
  )

  try {
    $argsIn = Get-C2FInputArgs -CliArgs $CliArgs
    Write-C2FLog -Action $ActionName -Message "Started"

    switch ($ActionName) {
      "firewall-drop" {
        $ip = Get-C2FArg -Args $argsIn -Index 0 -Name "ip"
        if (-not (Test-C2FIpAddress -Ip $ip)) { throw "Invalid IP address: $ip" }
        $ruleName = "C2F-firewall-drop-$ip"
        & netsh advfirewall firewall add rule name="$ruleName" dir=in action=block remoteip="$ip" | Out-Null
      }
      "host-deny" {
        $ip = Get-C2FArg -Args $argsIn -Index 0 -Name "ip"
        if (-not (Test-C2FIpAddress -Ip $ip)) { throw "Invalid IP address: $ip" }
        $ruleName = "C2F-host-deny-$ip"
        & netsh advfirewall firewall add rule name="$ruleName" dir=in action=block remoteip="$ip" | Out-Null
      }
      "netsh" {
        $ip = Get-C2FArg -Args $argsIn -Index 0 -Name "ip"
        if (-not (Test-C2FIpAddress -Ip $ip)) { throw "Invalid IP address: $ip" }
        $ruleName = "C2F-netsh-$ip"
        & netsh advfirewall firewall add rule name="$ruleName" dir=in action=block remoteip="$ip" | Out-Null
      }
      "route-null" {
        $ip = Get-C2FArg -Args $argsIn -Index 0 -Name "ip"
        if (-not (Test-C2FIpAddress -Ip $ip)) { throw "Invalid IP address: $ip" }
        & route.exe DELETE $ip | Out-Null
        & route.exe ADD $ip MASK 255.255.255.255 0.0.0.0 | Out-Null
      }
      "win_route-null" {
        $ip = Get-C2FArg -Args $argsIn -Index 0 -Name "ip"
        if (-not (Test-C2FIpAddress -Ip $ip)) { throw "Invalid IP address: $ip" }
        & route.exe DELETE $ip | Out-Null
        & route.exe ADD $ip MASK 255.255.255.255 0.0.0.0 | Out-Null
      }
      "kill-process" {
        $pidRaw = Get-C2FArg -Args $argsIn -Index 0 -Name "pid"
        $pid = 0
        if (-not [int]::TryParse($pidRaw, [ref]$pid)) {
          throw "Invalid pid: $pidRaw"
        }
        Stop-Process -Id $pid -Force -ErrorAction Stop
      }
      "quarantine-file" {
        $path = Get-C2FArg -Args $argsIn -Index 0 -Name "path"
        if (-not (Test-Path $path)) {
          throw "File not found: $path"
        }
        $dayDir = Join-Path $script:QuarantineDir (Get-Date -Format "yyyyMMdd")
        if (-not (Test-Path $dayDir)) {
          New-Item -ItemType Directory -Path $dayDir -Force | Out-Null
        }
        $dest = Join-Path $dayDir ((Get-Date -Format "HHmmss") + "_" + (Split-Path $path -Leaf))
        Move-Item -Path $path -Destination $dest -Force
      }
      "malware-scan" {
        $scope = if ($argsIn.Count -gt 0) { "$($argsIn[0])" } else { "quick" }
        if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
          switch ($scope.ToLowerInvariant()) {
            "quick" { Start-MpScan -ScanType QuickScan }
            "full" { Start-MpScan -ScanType FullScan }
            default {
              if (-not (Test-Path $scope)) { throw "Custom scan path not found: $scope" }
              Start-MpScan -ScanType CustomScan -ScanPath $scope
            }
          }
          $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 50
          $report = @{ scope = $scope; threats = $threats }
          [void](Save-C2FReport -Action $ActionName -Payload $report)
        }
        else {
          throw "Windows Defender cmdlets unavailable"
        }
      }
      "sca-rescan" {
        $service = Get-C2FServiceName -Names @("WazuhSvc", "Wazuh")
        if (-not $service) {
          throw "Wazuh service not found"
        }
        Restart-Service -Name $service -Force -ErrorAction Stop
      }
      "restart-wazuh" {
        $service = Get-C2FServiceName -Names @("WazuhSvc", "Wazuh")
        if (-not $service) {
          throw "Wazuh service not found"
        }
        Restart-Service -Name $service -Force -ErrorAction Stop
      }
      "patch-linux" {
        throw "patch-linux is not supported on Windows endpoints"
      }
      "collect-forensics" {
        $runDir = Join-Path $script:OutputDir ("forensics_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
        New-Item -ItemType Directory -Path $runDir -Force | Out-Null

        Get-ComputerInfo | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $runDir "computer.json") -Encoding UTF8
        Get-Process | Select-Object Id, ProcessName, Path, CPU, StartTime | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $runDir "processes.json") -Encoding UTF8
        Get-Service | Select-Object Name, Status, StartType | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $runDir "services.json") -Encoding UTF8
        Get-ScheduledTask | Select-Object TaskName, TaskPath, State | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $runDir "scheduled_tasks.json") -Encoding UTF8
        Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $runDir "net_connections.json") -Encoding UTF8

        $zipPath = $runDir + ".zip"
        Compress-Archive -Path (Join-Path $runDir "*") -DestinationPath $zipPath -Force
        Remove-Item -Path $runDir -Recurse -Force
      }
      "disable-account" {
        $user = Get-C2FArg -Args $argsIn -Index 0 -Name "user"
        & net.exe user "$user" /active:no | Out-Null
        if ($LASTEXITCODE -ne 0) {
          throw "Failed to disable user account: $user"
        }
      }
      "ioc-scan" {
        $indicator = Get-C2FArg -Args $argsIn -Index 0 -Name "ioc_set_or_indicator"
        $escaped = [regex]::Escape($indicator)

        $procMatches = Get-Process -ErrorAction SilentlyContinue | Where-Object {
          $_.ProcessName -match $escaped -or $_.Path -match $escaped
        } | Select-Object Id, ProcessName, Path

        $startupDirs = @(
          "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
          "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        $fileMatches = @()
        foreach ($dir in $startupDirs) {
          if (Test-Path $dir) {
            $fileMatches += Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
              $_.FullName -match $escaped -or $_.Name -match $escaped
            } | Select-Object FullName, Length, LastWriteTime
          }
        }

        $report = @{
          indicator = $indicator
          process_matches = $procMatches
          file_matches = $fileMatches
          generated_at = (Get-Date).ToString("o")
        }
        [void](Save-C2FReport -Action $ActionName -Payload $report)
      }
      "yara-scan" {
        $targetPath = if ($argsIn.Count -gt 0) { "$($argsIn[0])" } else { "C:\Users" }
        if (-not (Test-Path $targetPath)) {
          throw "Scan path not found: $targetPath"
        }
        $rulePath = Join-Path $PSScriptRoot "rules\default.yar"
        if (-not (Test-Path $rulePath)) {
          throw "YARA rule file missing: $rulePath"
        }
        $yaraExe = Find-C2FYaraExe
        if (-not $yaraExe) {
          throw "YARA executable not found (yara.exe/yara64.exe)"
        }

        $output = & $yaraExe -r $rulePath $targetPath 2>&1
        $report = @{
          target = $targetPath
          rule = $rulePath
          output = $output
          generated_at = (Get-Date).ToString("o")
        }
        [void](Save-C2FReport -Action $ActionName -Payload $report)
      }
      "collect-memory" {
        # RAM Safety Gate: Fail if Free RAM < 500MB
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($osInfo) {
          $freeMemoryMB = [math]::Round($osInfo.FreePhysicalMemory / 1024)
          $totalMemoryMB = [math]::Round($osInfo.TotalVisibleMemorySize / 1024)
          if ($freeMemoryMB -lt 500) {
            throw "Insufficient free RAM: $freeMemoryMB MB available (< 500 MB threshold). Cannot safely collect memory."
          }
        }

        $target = Get-Process -Name "ossec-agent" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $target) {
          $target = Get-Process -Name "wazuh-agent" -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        if (-not $target) {
          $target = Get-Process -Id $PID -ErrorAction SilentlyContinue
        }

        # Collect comprehensive process telemetry
        $allProcesses = @()
        try {
          $allProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            @{
              ProcessId = $_.ProcessId
              ParentProcessId = $_.ParentProcessId
              Name = $_.Name
              CommandLine = $_.CommandLine
              Priority = $_.Priority
              CreationTime = $_.CreationTime
              Owner = ""
              OwnerSID = ""
            }
          }
        } catch { }

        # Collect process-to-TCP/UDP connection mapping
        $connections = @()
        try {
          $netConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State
          $netConnections += Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object OwningProcess, LocalAddress, LocalPort
          foreach ($conn in $netConnections) {
            $proc = $allProcesses | Where-Object { $_.ProcessId -eq $conn.OwningProcess } | Select-Object -First 1
            if ($proc) {
              $connections += @{
                ProcessId = $conn.OwningProcess
                ProcessName = $proc.Name
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State
              }
            }
          }
        } catch { }

        # Attempt full memory dump
        $dumpCreated = $false
        $dumpPath = Join-Path $script:OutputDir ("memory_" + $target.Id + "_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".dmp")
        try {
          $comsvcs = Join-Path $env:SystemRoot "System32\comsvcs.dll"
          if (Test-Path $comsvcs) {
            $argList = "$comsvcs, MiniDump $($target.Id) $dumpPath full"
            Start-Process -FilePath "rundll32.exe" -ArgumentList $argList -NoNewWindow -Wait
            if (Test-Path $dumpPath) {
              $dumpCreated = $true
            }
          }
        } catch {
          $dumpCreated = $false
        }

        # Save comprehensive telemetry report
        $report = @{
          timestamp = (Get-Date).ToString("o")
          target_process = @{
            id = $target.Id
            name = $target.ProcessName
            command_line = $target.CommandLine
          }
          free_memory_mb = if ($osInfo) { [math]::Round($osInfo.FreePhysicalMemory / 1024) } else { "unknown" }
          total_memory_mb = if ($osInfo) { [math]::Round($osInfo.TotalVisibleMemorySize / 1024) } else { "unknown" }
          memory_dump = @{
            created = $dumpCreated
            path = if ($dumpCreated) { $dumpPath } else { "" }
          }
          processes = @($allProcesses | Select-Object -First 100)
          connections = @($connections | Select-Object -First 100)
          top_memory_consumers = @(Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 20 -Property Id, ProcessName, WorkingSet64)
          generated_at = (Get-Date).ToString("o")
        }
        [void](Save-C2FReport -Action $ActionName -Payload $report)
      }
      "hash-blocklist" {
        $hash = Get-C2FArg -Args $argsIn -Index 0 -Name "sha256"
        if ($hash -notmatch '^[A-Fa-f0-9]{64}$') {
          throw "Invalid SHA256 hash"
        }
        $normalized = $hash.ToUpperInvariant()
        
        # Ensure blocklist file exists
        if (-not (Test-Path $script:BlocklistFile)) {
          New-Item -ItemType File -Path $script:BlocklistFile -Force | Out-Null
        }
        
        # Add hash to blocklist if not already present
        $existing = @(Get-Content -Path $script:BlocklistFile -ErrorAction SilentlyContinue | Where-Object { $_ })
        if ($existing -notcontains $normalized) {
          Add-Content -Path $script:BlocklistFile -Value $normalized
        }
        
        # Enforce: Check for running processes with this hash and kill them
        $blockedCount = 0
        try {
          $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
          foreach ($proc in $processes) {
            if (-not $proc.ExecutablePath) { continue }
            try {
              $fileHash = Get-FileHash -Path $proc.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue
              if ($fileHash -and $fileHash.Hash.ToUpperInvariant() -eq $normalized) {
                Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
                $blockedCount++
              }
            } catch { }
          }
        } catch { }
        
        # Log enforcement action
        Write-C2FLog -Action $ActionName -Message "Added hash $normalized to blocklist; terminated $blockedCount running process(es)"
      }
      "service-restart" {
        $serviceName = Get-C2FArg -Args $argsIn -Index 0 -Name "service"
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $svc) {
          throw "Service not found: $serviceName"
        }
        Restart-Service -Name $serviceName -Force -ErrorAction Stop
      }
      "threat-hunt-persistence" {
        # Registry-based persistence: Run keys
        $runKeys = @(
          "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
          "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
          "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
          "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )

        $registryEntries = @()
        foreach ($key in $runKeys) {
          if (Test-Path $key) {
            $item = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($item) {
              $props = $item.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") }
              foreach ($prop in $props) {
                $entry = @{
                  key = $key
                  name = $prop.Name
                  value = "$($prop.Value)"
                  risk_flags = @()
                }
                # Risk detection
                $value = "$($prop.Value)".ToLower()
                if ($value -match '(powershell|cmd|rundll|regsvr|cscript|wscript)') { $entry.risk_flags += "suspicious_interpreter" }
                if ($value -match '(encoded|enc |base64)') { $entry.risk_flags += "encoded_payload" }
                $registryEntries += $entry
              }
            }
          }
        }

        # File-based persistence: Startup directories
        $startupDirs = @(
          "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
          "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        $startupFiles = @()
        foreach ($dir in $startupDirs) {
          if (Test-Path $dir) {
            $files = Get-ChildItem -Path $dir -File -Recurse -ErrorAction SilentlyContinue
            foreach ($file in $files) {
              $fileEntry = @{
                FullName = $file.FullName
                LastWriteTime = $file.LastWriteTime.ToString("o")
                Length = $file.Length
                Extension = $file.Extension
                Signed = $false
                SignatureStatus = "Unknown"
              }
              # Check digital signature
              try {
                $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                if ($sig) {
                  $fileEntry.Signed = ($sig.Status -eq "Valid")
                  $fileEntry.SignatureStatus = [string]$sig.Status
                  $fileEntry.SignatureThumbprint = $sig.SignerCertificate.Thumbprint
                }
              } catch { }
              $startupFiles += $fileEntry
            }
          }
        }

        # Scheduled Tasks persistence
        $scheduledTasks = @()
        try {
          $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
          foreach ($task in $tasks) {
            if ($task.Principal.RunLevel -eq "Highest" -or $task.Principal.UserId -eq "SYSTEM") {
              try {
                $taskState = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $action = $task.Actions[0]
                if ($action) {
                  $taskEntry = @{
                    TaskName = $task.TaskName
                    TaskPath = $task.TaskPath
                    Enabled = $task.Settings.Enabled
                    RunLevel = $task.Principal.RunLevel
                    UserId = $task.Principal.UserId
                    LastRunTime = if ($taskState) { $taskState.LastRunTime.ToString("o") } else { "" }
                    Action = $action.Execute
                    ActionArgs = $action.Arguments
                  }
                  $scheduledTasks += $taskEntry
                }
              } catch { }
            }
          }
        } catch { }

        # WMI Event Subscription persistence
        $wmiSubscriptions = @()
        try {
          $wmiSubs = Get-CimInstance __EventFilter -Namespace root\subscription -ErrorAction SilentlyContinue
          foreach ($sub in $wmiSubs) {
            $wmiSubscriptions += @{
              Name = $sub.Name
              Query = $sub.QueryLanguage
              EventNamespace = $sub.EventNamespace
            }
          }
        } catch { }

        # Generate comprehensive report
        $report = @{
          timestamp = (Get-Date).ToString("o")
          registry_entries = @($registryEntries)
          startup_files = @($startupFiles)
          scheduled_tasks = @($scheduledTasks | Where-Object { $_ })
          wmi_subscriptions = @($wmiSubscriptions)
          suspicious_count = @($registryEntries | Where-Object { $_.risk_flags.Count -gt 0 }).Count + @($startupFiles | Where-Object { -not $_.Signed }).Count
          generated_at = (Get-Date).ToString("o")
        }
        [void](Save-C2FReport -Action $ActionName -Payload $report)
      }
      "rollback-kb" {
        $kbInput = Get-C2FArg -Args $argsIn -Index 0 -Name "kb"
        $kb = Normalize-C2FKb -Input $kbInput
        if (-not $kb) {
          throw "Invalid KB value: $kbInput"
        }
        $wusa = Join-Path $env:SystemRoot "System32\wusa.exe"
        if (-not (Test-Path $wusa)) {
          throw "wusa.exe not found"
        }
        Start-Process -FilePath $wusa -ArgumentList "/uninstall /kb:$kb /quiet /norestart" -NoNewWindow -Wait
      }
      default {
        throw "Unsupported action script: $ActionName"
      }
    }

    Write-C2FLog -Action $ActionName -Message "Completed successfully"
    exit 0
  }
  catch {
    Write-C2FLog -Action $ActionName -Message ("Failed: " + $_.Exception.Message)
    exit 1
  }
}
