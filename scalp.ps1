# ======================================================
# WINDOWS 11 LTSC HARDENING SCRIPT - GOD-TIER LOCKDOWN
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
# SECTION 5: Set DNS to Quad9 (9.9.9.9)
# --------------------------------------------
$iface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
Set-DnsClientServerAddress -InterfaceIndex $iface.InterfaceIndex -ServerAddresses ("9.9.9.9", "149.112.112.112")

# --------------------------------------------
# SECTION 6: Global Outbound Firewall Block
# --------------------------------------------
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block

# --------------------------------------------
# SECTION 7: Allow Firefox Browser
# --------------------------------------------
$firefox = "C:\Program Files\Mozilla Firefox\firefox.exe"
New-NetFirewallRule -DisplayName "ALLOW Firefox" -Direction Outbound -Program $firefox -Action Allow -Enabled True

# --------------------------------------------
# SECTION 8: Allow Telegram Desktop
# --------------------------------------------
$telegram = "$env:APPDATA\Telegram Desktop\Telegram.exe"
New-NetFirewallRule -DisplayName "ALLOW Telegram" -Direction Outbound -Program $telegram -Action Allow -Enabled True

# --------------------------------------------
# SECTION 9: Allow DNS, DHCP, NTP via svchost
# --------------------------------------------
New-NetFirewallRule -DisplayName "ALLOW DNS OUT" -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" -Protocol UDP -RemotePort 53 -Action Allow

New-NetFirewallRule -DisplayName "ALLOW DHCP OUT" -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" -Protocol UDP -RemotePort 67 -Action Allow

New-NetFirewallRule -DisplayName "ALLOW DHCP IN" -Direction Inbound `
  -Program "C:\Windows\System32\svchost.exe" -Protocol UDP -LocalPort 68 -Action Allow

New-NetFirewallRule -DisplayName "ALLOW NTP OUT" -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" -Protocol UDP -RemotePort 123 -Action Allow

# --------------------------------------------
# SECTION 10: BLOCK all other svchost outbound
# --------------------------------------------
New-NetFirewallRule -DisplayName "BLOCK svchost OUTBOUND" `
  -Program "C:\Windows\System32\svchost.exe" -Direction Outbound -Action Block -Enabled True

# --------------------------------------------
# SECTION 11: BLOCK Telemetry Domains via FQDN
# --------------------------------------------
$domains = @(
  "vortex.data.microsoft.com",
  "telemetry.microsoft.com",
  "watson.telemetry.microsoft.com",
  "watson.ppe.telemetry.microsoft.com",
  "settings-win.data.microsoft.com",
  "cs1.wpc.v0cdn.net",
  "a-0001.a-msedge.net",
  "fe2.update.microsoft.com.akadns.net",
  "ssw.live.com"
)
foreach ($domain in $domains) {
  New-NetFirewallRule -DisplayName "BLOCK $domain" `
    -RemoteFQDN $domain -Direction Outbound -Action Block
}

# --------------------------------------------
# SECTION 12: BLOCK All Remaining Traffic (Failsafe)
# --------------------------------------------
New-NetFirewallRule -DisplayName "BLOCK ALL REMAINING" `
  -Direction Outbound -Action Block -Enabled True

# --------------------------------------------
# SECTION 13: Final Confirmation
# --------------------------------------------
Write-Host "`n🔥 HARDENING COMPLETE: Only Firefox, Telegram, DNS, DHCP, and NTP allowed. svchost chained. Microsoft gagged. You are now a digital specter. 🔥`n"
