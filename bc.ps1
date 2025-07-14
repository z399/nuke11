# ======================================================
# WINDOWS 11 LTSC HARDENING SCRIPT - FULL LOCKDOWN MODE
# Author: Ruthless Bastard Ops
# Purpose: Harden system by killing telemetry, disabling updates,
#          and whitelisting only essential network traffic
# ======================================================

# ----------------------------
# SECTION 1: Kill telemetry services
# ----------------------------
$telemetryServices = @(
  "DiagTrack",           # Telemetry backbone
  "dmwappushservice",    # WAP push telemetry
  "WdiServiceHost",      # Diagnostic host
  "WdiSystemHost",       # System diagnostic host
  "WerSvc",              # Error reporting
  "PcaSvc"               # Compatibility assistant telemetry
)
foreach ($svc in $telemetryServices) {
  Stop-Service $svc -Force -ErrorAction SilentlyContinue
  Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# ----------------------------
# SECTION 2: Disable telemetry scheduled tasks
# ----------------------------
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

# ----------------------------
# SECTION 3: Disable telemetry in registry
# ----------------------------
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

# ----------------------------
# SECTION 4: Disable Windows Update stack
# ----------------------------
Stop-Service wuauserv -Force
Set-Service wuauserv -StartupType Disabled

Stop-Service WaaSMedicSvc -Force
Set-Service WaaSMedicSvc -StartupType Disabled

Stop-Service bits -Force
Set-Service bits -StartupType Disabled

# ----------------------------
# SECTION 5: Default deny - block all outbound traffic
# ----------------------------
New-NetFirewallRule -DisplayName "BLOCK ALL OUTBOUND" `
  -Direction Outbound `
  -Action Block `
  -Enabled True

# ----------------------------
# SECTION 6: Whitelist Firefox browser
# ----------------------------
New-NetFirewallRule -DisplayName "ALLOW Firefox" `
  -Direction Outbound `
  -Program "C:\Program Files\Mozilla Firefox\firefox.exe" `
  -Action Allow `
  -Enabled True

# ----------------------------
# SECTION 7: Whitelist Telegram desktop client
# ----------------------------
New-NetFirewallRule -DisplayName "ALLOW Telegram" `
  -Direction Outbound `
  -Program "$env:APPDATA\Telegram Desktop\Telegram.exe" `
  -Action Allow `
  -Enabled True

# ----------------------------
# SECTION 8: Allow DHCP for dynamic IP
# ----------------------------
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

# ----------------------------
# SECTION 9: Set DNS to Quad9 (secure provider)
# ----------------------------
$interface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ServerAddresses ("9.9.9.9", "149.112.112.112")

# ----------------------------
# SECTION 10: Allow DNS, NTP, Ping, svchost loopback
# ----------------------------
New-NetFirewallRule -DisplayName "ALLOW DNS OUT (UDP 53)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 53 `
  -Action Allow

New-NetFirewallRule -DisplayName "ALLOW NTP OUT (UDP 123)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 123 `
  -Action Allow

New-NetFirewallRule -DisplayName "ALLOW ICMP OUT" `
  -Protocol ICMPv4 `
  -Direction Outbound `
  -Action Allow

New-NetFirewallRule -DisplayName "ALLOW svchost LOOPBACK" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -RemoteAddress "127.0.0.1" `
  -Action Allow

# ----------------------------
# SECTION 11: Block all other svchost outbound traffic
# ----------------------------
New-NetFirewallRule -DisplayName "BLOCK svchost.exe OUTBOUND" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Action Block

# ----------------------------
# SECTION 12: Hostfile blackhole known telemetry domains
# ----------------------------
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

# ----------------------------
# SECTION 13: Confirmation
# ----------------------------
Write-Host "`nLOCKDOWN COMPLETE — Firefox, Telegram, DHCP, DNS, NTP whitelisted. Windows Update & telemetry killed. All other apps blocked.`n"
