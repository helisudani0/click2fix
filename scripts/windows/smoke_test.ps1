param(
  [string]$BaseUrl = "http://localhost:8000",
  [string]$Username = "admin",
  [string]$Password = "admin123",
  [string]$TestActionId = "endpoint-healthcheck",
  [bool]$UseApprovalFlow = $false,
  [int]$ExecutionPollSeconds = 30
)

function First-NonEmpty {
  param([object[]]$Values)
  foreach ($v in $Values) {
    if ($null -ne $v -and "$v".Length -gt 0) {
      return $v
    }
  }
  return $null
}

function Get-FirstItem {
  param($Data)
  if ($Data -is [System.Array]) { return $Data[0] }
  if ($Data.data -and $Data.data.affected_items) { return $Data.data.affected_items[0] }
  if ($Data.affected_items) { return $Data.affected_items[0] }
  if ($Data.items) { return $Data.items[0] }
  return $null
}

function To-Items {
  param($Data)
  if ($Data -is [System.Array]) { return $Data }
  if ($Data.data -and $Data.data.affected_items) { return $Data.data.affected_items }
  if ($Data.affected_items) { return $Data.affected_items }
  if ($Data.items) { return $Data.items }
  if ($null -ne $Data) { return @($Data) }
  return @()
}

function Build-ActionArgs {
  param($Action)
  $args = @{}
  if (-not $Action -or -not $Action.inputs) {
    return $args
  }
  foreach ($input in $Action.inputs) {
    switch ($input.name) {
      "ip" { $args[$input.name] = "1.2.3.4" }
      "pid" { $args[$input.name] = "1234" }
      "path" { $args[$input.name] = "C:\\Windows\\Temp\\sample.exe" }
      "scope" { $args[$input.name] = "quick" }
      "user" { $args[$input.name] = "test-user" }
      "ioc_set" { $args[$input.name] = "smoke-test" }
      "sha256" { $args[$input.name] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
      "service" { $args[$input.name] = "wazuh-agent" }
      "kb" { $args[$input.name] = "KB5001716" }
      default { $args[$input.name] = "test" }
    }
  }
  return $args
}

Write-Host "== Health =="
Invoke-RestMethod "$BaseUrl/health"

Write-Host "== Login =="
$login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" -Body @{
  username = $Username
  password = $Password
}
$token = $login.access_token
if (-not $token) {
  throw "Login failed - no access_token"
}
$headers = @{ Authorization = "Bearer $token" }

Write-Host "== Actions =="
$actions = Invoke-RestMethod "$BaseUrl/api/actions" -Headers $headers
$actionItems = To-Items $actions
$action = $actionItems | Where-Object { $_.id -eq $TestActionId } | Select-Object -First 1
if ($null -eq $action) {
  $action = $actionItems | Where-Object { -not $_.inputs -or $_.inputs.Count -eq 0 } | Select-Object -First 1
}
if ($null -eq $action) {
  $action = Get-FirstItem $actions
}
if ($null -eq $action) {
  Write-Host "No actions configured."
} else {
  Write-Host "Selected action for test: $($action.id)"
}

Write-Host "== Agents =="
$agents = Invoke-RestMethod "$BaseUrl/api/agents" -Headers $headers
$agentItem = Get-FirstItem $agents
$agentId = $null
if ($null -ne $agentItem) {
  $agentId = First-NonEmpty @($agentItem.id, $agentItem.agent_id, $agentItem.name, $agentItem.hostname)
}
if (-not $agentId) {
  Write-Host "No agents found."
}

Write-Host "== Alerts (limit=5) =="
$alerts = Invoke-RestMethod "$BaseUrl/api/alerts?limit=5" -Headers $headers
$alertItem = Get-FirstItem $alerts
$alertId = $null
if ($null -ne $alertItem) {
  $alertId = First-NonEmpty @($alertItem.id, $alertItem._id, $alertItem.alert_id)
}
Write-Host "Alerts fetched."

Write-Host "== Integration Status =="
Invoke-RestMethod "$BaseUrl/api/integration/status" -Headers $headers

Write-Host "== Analytics Overview =="
Invoke-RestMethod "$BaseUrl/api/analytics/overview" -Headers $headers | Out-Null
Write-Host "Overview OK."

Write-Host "== Analytics Kill-Chain =="
Invoke-RestMethod "$BaseUrl/api/analytics/kill-chain" -Headers $headers | Out-Null
Write-Host "Kill-chain OK."

Write-Host "== Analytics Hourly =="
Invoke-RestMethod "$BaseUrl/api/analytics/hourly?hours=24" -Headers $headers | Out-Null
Write-Host "Hourly OK."

Write-Host "== Generate Playbook =="
$pb = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/playbooks/generate" -Headers $headers `
  -ContentType "application/json" -Body (@{
    alert_id = $alertId
  } | ConvertTo-Json -Depth 4)
if ($pb) {
  Write-Host "Generated playbook: $($pb.name)"
}

if ($alertId) {
  Write-Host "== Alert Summary ($alertId) =="
  Invoke-RestMethod "$BaseUrl/api/analytics/alert/$alertId" -Headers $headers | Out-Null
  Write-Host "Alert summary OK."
} else {
  Write-Host "No alert ID available for summary."
}

Write-Host "== Audit Log =="
Invoke-RestMethod "$BaseUrl/api/audit?limit=5" -Headers $headers | Out-Null
Write-Host "Audit OK."

Write-Host "== Change Request =="
$change = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/changes" -Headers $headers `
  -ContentType "application/json" -Body (@{
    title = "Smoke Test Change"
    description = "Change created by smoke test"
    action_id = "firewall-drop"
    target = "group:all"
    risk_score = 20
    impact = "low"
    justification = "Smoke test"
  } | ConvertTo-Json -Depth 4)
if ($change.id) {
  Write-Host "Change created: $($change.id)"
}

if ($agentId -and $action) {
  $args = Build-ActionArgs $action
  $directPayload = @{
    agent_id = $agentId
    action_id = $action.id
    args = $args
  }

  Write-Host "== Direct Remediation Run =="
  try {
    $directRun = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/remediate" `
      -Headers $headers -ContentType "application/json" -Body ($directPayload | ConvertTo-Json -Depth 6)
    Write-Host "Direct run accepted:"
    Write-Host ($directRun | ConvertTo-Json -Depth 6)
  } catch {
    Write-Host "Direct remediation run failed: $($_.Exception.Message)"
  }

  if ($UseApprovalFlow) {
    Write-Host "== Request Approval =="
    $approvalPayload = @{
      agent_id = $agentId
      action_id = $action.id
      args = $args
      alert_id = "smoke-test"
      alert = @{ rule = "SmokeTest"; agent = $agentId; level = "1"; timestamp = (Get-Date).ToString("o") }
    } | ConvertTo-Json -Depth 6

    $approvalResponse = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/approvals/request" `
      -Headers $headers -ContentType "application/json" -Body $approvalPayload
    $approvalId = First-NonEmpty @($approvalResponse.id, $approvalResponse.approval_id)
    if (-not $approvalId) {
      throw "Approval request did not return an approval ID."
    }
    Write-Host "Approval requested: $approvalId"

    Write-Host "== Approve Request =="
    $approveResponse = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/approvals/$approvalId/approve" -Headers $headers
    $executionId = First-NonEmpty @($approveResponse.execution_id)
    Write-Host "Approve response status: $($approveResponse.status)"
    if (-not $executionId) {
      Write-Host "No execution ID returned (approval may still be in review)."
    } else {
      Write-Host "Execution started: $executionId"
      $deadline = (Get-Date).AddSeconds($ExecutionPollSeconds)
      $finalExecution = $null
      do {
        Start-Sleep -Seconds 2
        $execItems = To-Items (Invoke-RestMethod "$BaseUrl/api/approvals/executions" -Headers $headers)
        $finalExecution = $execItems | Where-Object { "$($_.id)" -eq "$executionId" } | Select-Object -First 1
        if ($finalExecution -and ($finalExecution.status -eq "SUCCESS" -or $finalExecution.status -eq "FAILED")) {
          break
        }
      } while ((Get-Date) -lt $deadline)

      if ($finalExecution) {
        Write-Host "Execution status: $($finalExecution.status)"
        $steps = Invoke-RestMethod "$BaseUrl/api/approvals/executions/$executionId" -Headers $headers
        $stepItems = To-Items $steps
        if ($stepItems.Count -gt 0) {
          $lastStep = $stepItems[-1]
          Write-Host "Last step: $($lastStep.step) / $($lastStep.status)"
        }
      } else {
        Write-Host "Execution not visible yet (timed out waiting)."
      }
    }
  } else {
    Write-Host "Approval flow skipped (UseApprovalFlow=false)."
  }
} else {
  Write-Host "Skipping action execution tests (no agent or action)."
}

Write-Host "== Done =="
