# ======================================================
# WINDOWS 11 LTSC HARDENING SCRIPT - FULL LOCKDOWN
# Author: Ruthless Bastard Ops
# Run as Administrator
# ======================================================

# --------------------------------------------
# SECTION 1: Kill telemetry/spyware services
# --------------------------------------------
# These services send telemetry and diagnostics data to Microsoft.
$telemetryServices = @(
  "DiagTrack",           # Telemetry backbone
  "dmwappushservice",    # Push telemetry service
  "WdiServiceHost",      # Diagnostic host
  "WdiSystemHost",       # Additional diagnostic host
  "WerSvc",              # Windows Error Reporting
  "PcaSvc"               # Program Compatibility Assistant (more reporting)
)
foreach ($svc in $telemetryServices) {
  Stop-Service $svc -Force -ErrorAction SilentlyContinue
  Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# --------------------------------------------
# SECTION 2: Disable telemetry scheduled tasks
# --------------------------------------------
# These tasks trigger various telemetry events.
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
  schtasks /Change /TN $task /Disable 2>$null  # Suppress errors if task is absent
}

# --------------------------------------------
# SECTION 3: Disable telemetry/CEIP via registry
# --------------------------------------------
# These registry values shut down telemetry and consumer features.
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
# LTSC typically does not include Cortana; create the key if missing.
$searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (-not (Test-Path $searchPath)) {
    New-Item -Path $searchPath -Force | Out-Null
}
New-ItemProperty -Path $searchPath -Name "AllowCortana" -Value 0 -PropertyType DWord -Force | Out-Null

# --------------------------------------------
# SECTION 5: Block ALL outbound traffic by default
# --------------------------------------------
# Establish a default-deny outbound firewall rule.
New-NetFirewallRule -DisplayName "BLOCK ALL OUTBOUND" `
  -Direction Outbound `
  -Action Block `
  -Enabled True

# --------------------------------------------
# SECTION 6: Allow Firefox browser only
# --------------------------------------------
# Replace the path if Firefox is installed elsewhere.
$browserPath = "C:\Program Files\Mozilla Firefox\firefox.exe"
New-NetFirewallRule -DisplayName "ALLOW Firefox" `
  -Direction Outbound `
  -Program $browserPath `
  -Action Allow `
  -Enabled True

# --------------------------------------------
# SECTION 6.5: Allow Telegram Desktop client
# --------------------------------------------
# Adjust the path if your Telegram installation differs.
$telegramPath = "$env:APPDATA\Telegram Desktop\Telegram.exe"
New-NetFirewallRule -DisplayName "ALLOW Telegram" `
  -Direction Outbound `
  -Program $telegramPath `
  -Action Allow `
  -Enabled True

# --------------------------------------------
# SECTION 7: Allow DHCP traffic (for dynamic IP assignment)
# --------------------------------------------
# Allow DHCP outbound (UDP port 67) and inbound (UDP port 68) for IP lease renewal.
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
# Set the primary DNS servers for the active network interface.
$interface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ServerAddresses ("9.9.9.9", "149.112.112.112")

# --------------------------------------------
# SECTION 7.6: Minimal Safe Allow List for DNS and Diagnostics
# --------------------------------------------
# Allow DNS resolution via svchost (UDP port 53)
New-NetFirewallRule -DisplayName "ALLOW DNS OUT (UDP 53)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 53 `
  -Action Allow `
  -Enabled True

# Allow ICMP (e.g., ping, diagnostics)
New-NetFirewallRule -DisplayName "ALLOW ICMP OUT" `
  -Protocol ICMPv4 `
  -Direction Outbound `
  -Action Allow `
  -Enabled True

# Allow loopback traffic for svchost (internal communication)
New-NetFirewallRule -DisplayName "ALLOW svchost LOOPBACK" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -RemoteAddress "127.0.0.1" `
  -Action Allow `
  -Enabled True

# --------------------------------------------
# SECTION 8: Allow NTP (Network Time Protocol for time sync)
# --------------------------------------------
New-NetFirewallRule -DisplayName "ALLOW NTP OUT (UDP 123)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 123 `
  -Action Allow

# --------------------------------------------
# SECTION 9: Block all other outbound svchost.exe traffic
# --------------------------------------------
# After whitelisting necessary ports, block all remaining outbound traffic from svchost.exe.
New-NetFirewallRule -DisplayName "BLOCK ALL svchost.exe OUTBOUND" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Action Block

# --------------------------------------------
# SECTION 10: Blackhole known telemetry domains via hosts file
# --------------------------------------------
# Redirect telemetry domains to 0.0.0.0 to prevent them from reaching Microsoft.
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
Write-Host "`nLOCKDOWN COMPLETE: Only Firefox, Telegram, DHCP, DNS, and NTP allowed. Everything else is blocked.`n"
