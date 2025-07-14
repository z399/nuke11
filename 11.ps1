# ======================================================
# WINDOWS 11 LTSC HARDENING SCRIPT - FULL LOCKDOWN
# Author: Ruthless Bastard Ops
# Run this as Administrator
# ======================================================

# --------------------------------------------
# SECTION 1: Kill Microsoft telemetry/spyware services
# --------------------------------------------
# These services report usage, diagnostics, crash data, etc.
$telemetryServices = @(
  "DiagTrack",           # Telemetry backbone
  "dmwappushservice",    # Push telemetry service
  "WdiServiceHost",      # Diagnostic host
  "WdiSystemHost",       # Another diagnostic system host
  "WerSvc",              # Windows Error Reporting
  "PcaSvc"               # Program Compatibility Assistant (more reporting BS)
)
foreach ($svc in $telemetryServices) {
  Stop-Service $svc -Force -ErrorAction SilentlyContinue
  Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# --------------------------------------------
# SECTION 2: Disable telemetry-related scheduled tasks
# --------------------------------------------
# These auto-trigger data collection events—kill them
$telemetryTasks = @(
  "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
  "\Microsoft\Windows\Autochk\Proxy",
  "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
  "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
  "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
  "\Microsoft\Windows\Feedback\Siuf\DmClient",
  "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
  "\Microsoft\Windows\Maintenance\WinSAT",
  "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
  "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
)
foreach ($task in $telemetryTasks) {
  schtasks /Change /TN $task /Disable 2>$null  # Ignore error if task not found
}

# --------------------------------------------
# SECTION 3: Disable telemetry/CEIP (Customer Experience Program) via registry
# --------------------------------------------
# These registry values force Windows to fully shut down telemetry even in enterprise
$registryPaths = @(
  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SQMClient\Windows",
  "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows",
  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
)
foreach ($path in $registryPaths) {
  if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
  }
}
# Zero out telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
# Kill CEIP (Customer Experience)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
# Disable consumer experience crap
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerFeatures" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord

# --------------------------------------------
# SECTION 4: Disable Cortana/Online Search if key exists (skip error)
# --------------------------------------------
# LTSC doesn't have Cortana by default, so create key first
$searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (-not (Test-Path $searchPath)) {
    New-Item -Path $searchPath -Force | Out-Null
}
New-ItemProperty -Path $searchPath -Name "AllowCortana" -Value 0 -PropertyType DWord -Force | Out-Null

# --------------------------------------------
# SECTION 5: Block ALL outbound traffic (default deny)
# --------------------------------------------
# This sets up a default deny firewall posture
New-NetFirewallRule -DisplayName "BLOCK ALL OUTBOUND" `
  -Direction Outbound `
  -Action Block `
  -Enabled True

# --------------------------------------------
# SECTION 6: Allow Firefox browser ONLY
# --------------------------------------------
# Replace this path if you use a different browser or installed it elsewhere
$browserPath = "C:\Program Files\Mozilla Firefox\firefox.exe"
New-NetFirewallRule -DisplayName "ALLOW Firefox" `
  -Direction Outbound `
  -Program $browserPath `
  -Action Allow `
  -Enabled True

# --------------------------------------------
# SECTION 6.5: Allow Telegram Desktop client
# --------------------------------------------
# Adjust if your Telegram path is custom
$telegramPath = "$env:APPDATA\Telegram Desktop\Telegram.exe"
New-NetFirewallRule -DisplayName "ALLOW Telegram" `
  -Direction Outbound `
  -Program $telegramPath `
  -Action Allow `
  -Enabled True

# --------------------------------------------
# SECTION 7: Allow DHCP traffic (required for IP address)
# --------------------------------------------
# These two rules allow dynamic IP from router (DHCP client/server)
New-NetFirewallRule -DisplayName "ALLOW DHCP OUT (UDP 67)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 67 `
  -Action Allow

New-NetFirewallRule -DisplayName "ALLOW DHCP IN (UDP 68)" `
  -Direction Inbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -LocalPort 68 `
  -Action Allow

# --------------------------------------------
# SECTION 7.5: Set system DNS to Quad9 (secure, privacy-respecting DNS)
# --------------------------------------------
$interface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ServerAddresses ("9.9.9.9", "149.112.112.112")

# --------------------------------------------
# SECTION 7.6: Allow DNS lookups (UDP 53)
# --------------------------------------------
# Needed for resolving domains via svchost
New-NetFirewallRule -DisplayName "ALLOW DNS OUT (UDP 53)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 53 `
  -Action Allow

# --------------------------------------------
# SECTION 8: Allow NTP (time sync service)
# --------------------------------------------
# This keeps system time correct via network time
New-NetFirewallRule -DisplayName "ALLOW NTP OUT (UDP 123)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 123 `
  -Action Allow

# --------------------------------------------
# SECTION 9: Block ALL other svchost-based outbound traffic
# --------------------------------------------
# svchost is used by many services—block all but the few allowed above
New-NetFirewallRule -DisplayName "BLOCK ALL svchost.exe OUTBOUND" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Action Block

# --------------------------------------------
# SECTION 10: Blackhole Microsoft telemetry domains via hosts file
# --------------------------------------------
# DNS poisoning to ensure even hardcoded requests fail
$telemetryDomains = @"
0.0.0.0 vortex.data.microsoft.com
0.0.0.0 telemetry.microsoft.com
0.0.0.0 watson.telemetry.microsoft.com
0.0.0.0 watson.ppe.telemetry.microsoft.com
0.0.0.0 settings-win.data.microsoft.com
0.0.0.0 cs1.wpc.v0cdn.net
0.0.0.0 a-0001.a-msedge.net
0.0.0.0 fe2.update.microsoft.com.akadns.net
0.0.0.0 ssw.live.com
"@
Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value $telemetryDomains

# --------------------------------------------
# SECTION 11: Final confirmation
# --------------------------------------------
Write-Host "`nLOCKDOWN COMPLETE: Only Firefox, Telegram, DHCP, DNS, and NTP allowed. Everything else blocked.`n"
