# ================================
# nuke 11
# ================================
# Run as ADMINISTRATOR
# ================================

# ------------------------------
# SECTION 1: KILL TELEMETRY SERVICES
# ------------------------------
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

# ------------------------------
# SECTION 2: DISABLE TELEMETRY TASKS
# ------------------------------
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

# ------------------------------
# SECTION 3: TELEMETRY & CEIP REGISTRY NUKES
# ------------------------------
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

# ------------------------------
# SECTION 4: CORTANA AND ONLINE BS
# ------------------------------
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
  -Name "AllowCortana" -Value 0 -PropertyType DWord -Force | Out-Null

# ------------------------------
# SECTION 5: BLOCK ALL OUTBOUND TRAFFIC BY DEFAULT
# ------------------------------
New-NetFirewallRule -DisplayName "BLOCK ALL OUTBOUND" -Direction Outbound -Action Block -Enabled True

# ------------------------------
# SECTION 6: ALLOW FIREFOX BROWSER ONLY
# ------------------------------
# Firefox path – adjust if installed elsewhere
$browserPath = "C:\Program Files\Mozilla Firefox\firefox.exe"
New-NetFirewallRule -DisplayName "ALLOW Firefox Browser" `
  -Direction Outbound `
  -Program $browserPath `
  -Action Allow `
  -Enabled True

# ------------------------------
# SECTION 6.5: ALLOW TELEGRAM DESKTOP CLIENT
# ------------------------------
# Telegram default install path – verify on your system
$telegramPath = "$env:APPDATA\Telegram Desktop\Telegram.exe"
New-NetFirewallRule -DisplayName "ALLOW Telegram Desktop" `
  -Direction Outbound `
  -Program $telegramPath `
  -Action Allow `
  -Enabled True

# ------------------------------
# SECTION 7: ALLOW DHCP (GET IP VIA ROUTER)
# ------------------------------
New-NetFirewallRule -DisplayName "DHCP OUT (UDP 67)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 67 `
  -Action Allow

New-NetFirewallRule -DisplayName "DHCP IN (UDP 68)" `
  -Direction Inbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -LocalPort 68 `
  -Action Allow

# ------------------------------
# SECTION 7.5: SET SYSTEM-WIDE DNS TO MULLVAD ADBLOCK
# ------------------------------
$interface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ServerAddresses ("193.138.218.74", "185.213.26.187")

# ------------------------------
# SECTION 8: ALLOW TIME SYNC (NTP via port 123)
# ------------------------------
New-NetFirewallRule -DisplayName "NTP Time Sync (UDP 123)" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Protocol UDP `
  -RemotePort 123 `
  -Action Allow

# ------------------------------
# SECTION 9: BLOCK ALL OTHER svchost TRAFFIC
# ------------------------------
New-NetFirewallRule -DisplayName "BLOCK ALL OTHER svchost.exe" `
  -Direction Outbound `
  -Program "C:\Windows\System32\svchost.exe" `
  -Action Block

# ------------------------------
# SECTION 10: BLACKHOLE TELEMETRY DOMAINS IN HOSTS FILE
# ------------------------------
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

# ------------------------------
# DONE
# ------------------------------
Write-Host "`nLOCKDOWN COMPLETE`n"
