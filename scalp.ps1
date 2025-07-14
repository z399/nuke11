# ======================================================
# WINDOWS 11 LTSC HARDENING SCRIPT - SAFE NETWORK VERSION
# Author: Ruthless Bastard Ops
# Run as Administrator
# ======================================================

# --------------------------------------------
# SECTION 1: Kill telemetry/spyware services
# --------------------------------------------
$telemetryServices = @(
  "DiagTrack", "dmwappushservice", "WdiServiceHost",
  "WdiSystemHost", "WerSvc", "PcaSvc"
)
foreach ($svc in $telemetryServices) {
  Stop-Service $svc -Force -ErrorAction SilentlyContinue
  Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# --------------------------------------------
# SECTION 2: Disable telemetry scheduled tasks
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
  schtasks /Change /TN $task /Disable 2>$null
}

# --------------------------------------------
# SECTION 3: Disable telemetry/CEIP via registry
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
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerFeatures" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord

# --------------------------------------------
# SECTION 4: Optional Cortana/Online Search Disable
# --------------------------------------------
$searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (-not (Test-Path $searchPath)) {
    New-Item -Path $searchPath -Force | Out-Null
}
New-ItemProperty -Path $searchPath -Name "AllowCortana" -Value 0 -PropertyType DWord -Force | Out-Null

# --------------------------------------------
# SECTION 6: Allow Firefox browser only
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
# SECTION 7: Allow DHCP traffic
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
# SECTION 7.5: Set system DNS to Quad9
# --------------------------------------------
$interface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ServerAddresses ("9.9.9.9", "149.112.112.112")

# --------------------------------------------
# SECTION 7.6: Minimal Safe Allow List
# --------------------------------------------
New-NetFirewallRule -DisplayName "ALLOW DNS OUT (UDP 53)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 53 `
  -Action Allow `
  -Enabled True

New-NetFirewallRule -DisplayName "ALLOW ICMP OUT" `
  -Protocol ICMPv4 `
  -Direction Outbound `
  -Action Allow `
  -Enabled True

New-NetFirewallRule -DisplayName "ALLOW svchost LOOPBACK" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -RemoteAddress "127.0.0.1" `
  -Action Allow `
  -Enabled True

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
# SECTION 10: Blackhole known telemetry domains
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
# SECTION 11: Final confirmation message
# --------------------------------------------
Write-Host "`nSANITIZED LOCKDOWN: Telemetry wiped. Firefox, Telegram, DNS, DHCP, NTP permitted. No outbound block enforced.`n"
