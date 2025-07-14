# ======================================================
# Windows 11 LTSC HARDENING SCRIPT - FULL LOCKDOWN
# Author: Ruthless Bastard Ops
# Run this as Administrator
# ======================================================

# --------------------------------------------
# SECTION 1: Disable telemetry/spyware services
# --------------------------------------------
$telemetryServices = @(
  "DiagTrack",           # Connected User Experiences and Telemetry
  "dmwappushservice",    # WAP push telemetry
  "WdiServiceHost",      # Diagnostic System Host
  "WdiSystemHost",       # Diagnostic System Host
  "WerSvc",              # Windows Error Reporting
  "PcaSvc"               # Program Compatibility Assistant
)
foreach ($svc in $telemetryServices) {
  Stop-Service $svc -Force -ErrorAction SilentlyContinue
  Set-Service $svc -StartupType Disabled
}

# --------------------------------------------
# SECTION 2: Kill scheduled telemetry tasks
# --------------------------------------------
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
  schtasks /Change /TN $task /Disable
}

# --------------------------------------------
# SECTION 3: Registry nukes for telemetry/CEIP
# --------------------------------------------
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

# Disable telemetry and CEIP features
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerFeatures" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord

# --------------------------------------------
# SECTION 4: Kill Cortana/online features
# --------------------------------------------
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
  -Name "AllowCortana" -Value 0 -PropertyType DWord -Force | Out-Null

# --------------------------------------------
# SECTION 5: Block all outbound connections by default
# --------------------------------------------
New-NetFirewallRule -DisplayName "BLOCK ALL OUTBOUND" `
  -Direction Outbound `
  -Action Block `
  -Enabled True

# --------------------------------------------
# SECTION 6: Allow Firefox only
# --------------------------------------------
$browserPath = "C:\Program Files\Mozilla Firefox\firefox.exe"
New-NetFirewallRule -DisplayName "ALLOW Firefox" `
  -Direction Outbound `
  -Program $browserPath `
  -Action Allow `
  -Enabled True

# --------------------------------------------
# SECTION 6.5: Allow Telegram Desktop client
# --------------------------------------------
$telegramPath = "$env:APPDATA\Telegram Desktop\Telegram.exe"
New-NetFirewallRule -DisplayName "ALLOW Telegram" `
  -Direction Outbound `
  -Program $telegramPath `
  -Action Allow `
  -Enabled True

# --------------------------------------------
# SECTION 7: DHCP - Required for dynamic IP
# --------------------------------------------
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
# SECTION 7.5: Set DNS system-wide to Quad9 (secure DNS)
# --------------------------------------------
$interface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ServerAddresses ("9.9.9.9", "149.112.112.112")

# --------------------------------------------
# SECTION 7.6: Allow DNS resolution (UDP 53)
# --------------------------------------------
New-NetFirewallRule -DisplayName "ALLOW DNS OUT (UDP 53)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 53 `
  -Action Allow

# --------------------------------------------
# SECTION 8: Allow NTP (time sync)
# --------------------------------------------
New-NetFirewallRule -DisplayName "ALLOW NTP OUT (UDP 123)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 123 `
  -Action Allow

# --------------------------------------------
# SECTION 9: Block ALL other svchost traffic
# --------------------------------------------
New-NetFirewallRule -DisplayName "BLOCK ALL svchost.exe OUTBOUND" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Action Block

# --------------------------------------------
# SECTION 10: Blackhole telemetry domains (hosts file)
# --------------------------------------------
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
# SECTION 11: Lockdown Complete
# --------------------------------------------
Write-Host "`nLOCKDOWN COMPLETE: Only Firefox, Telegram, DHCP, DNS, and NTP allowed. Everything else is dead.`n"
