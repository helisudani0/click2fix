rule C2F_Suspicious_PowerShell
{
  strings:
    $a = "Invoke-Expression" nocase
    $b = "DownloadString" nocase
  condition:
    any of them
}
