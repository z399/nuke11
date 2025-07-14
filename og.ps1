# ==========================
# Brutal Windows 11 LTSC 2024 Hardening Script
# ==========================

# Step 1: Disable Telemetry + CEIP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetry /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f

# Step 2: Disable Feedback & Diagnostics
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInDays /t REG_DWORD /d 0 /f

# Step 3: Disable SmartScreen & Cloud Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent 2

# Step 4: Disable Defender (Optional)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true

# Step 5: Stop + Disable Update Services
Stop-Service wuauserv -Force
Set-Service wuauserv -StartupType Disabled
Stop-Service bits -Force
Set-Service bits -StartupType Disabled

# Disable Update Orchestrator Tasks
schtasks /Change /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Disable
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" /Disable

# Step 6: Block Known MS Telemetry Domains via Hosts File
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$blockList = @(
"0.0.0.0 telemetry.microsoft.com",
"0.0.0.0 watson.telemetry.microsoft.com",
"0.0.0.0 vortex.data.microsoft.com",
"0.0.0.0 settings-win.data.microsoft.com",
"0.0.0.0 fe2.update.microsoft.com",
"0.0.0.0 ssw.live.com",
"0.0.0.0 client.wns.windows.com"
)
Add-Content -Path $hostsPath -Value "`n# Microsoft Telemetry Blocklist"
$blockList | ForEach-Object { Add-Content -Path $hostsPath -Value $_ }

# Step 7: Configure Firewall to Block Everything by Default
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# Step 8: Allow Basic Programs (Example - Allow Only Firefox)
netsh advfirewall firewall add rule name="Allow Firefox" dir=out action=allow program="C:\Program Files\Mozilla Firefox\firefox.exe" enable=yes

# Step 9: Disable Cloud Content (Bing Search, Tips, Ads)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f

# Step 10: Disable Remote Registry and Remote Desktop
Stop-Service RemoteRegistry -Force
Set-Service RemoteRegistry -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f

# Step 11: Disable Hidden Telemetry Services (DiagTrack, dmwappush)
sc stop DiagTrack
sc config DiagTrack start= disabled
sc stop dmwappushservice
sc config dmwappushservice start= disabled

# Step 12: Protect Hosts File From Defender Interference
Add-MpPreference -ExclusionPath "C:\Windows\System32\drivers\etc"

Write-Host ">> Windows 11 LTSC 2024 hardening complete. System has been spiked and locked down." -ForegroundColor Green
