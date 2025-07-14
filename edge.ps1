# RUN AS ADMIN IN SAFE MODE — OR DON'T BOTHER

Write-Output ">> Nuking Microsoft Edge from the fucking system..."

# 1. Take ownership of Edge folders
$paths = @(
  "$env:ProgramFiles (x86)\Microsoft\Edge",
  "$env:ProgramFiles\Microsoft\Edge",
  "$env:ProgramFiles (x86)\Microsoft\EdgeUpdate",
  "$env:ProgramFiles\Microsoft\EdgeUpdate",
  "$env:ProgramData\Microsoft\Edge"
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        takeown /f "$path" /r /d Y
        icacls "$path" /grant administrators:F /t /c
        Remove-Item "$path" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 2. Kill scheduled update tasks
$tasks = @(
    "\Microsoft\EdgeUpdateTaskMachineCore",
    "\Microsoft\EdgeUpdateTaskMachineUA"
)
foreach ($task in $tasks) {
    schtasks /Delete /TN $task /F > $null 2>&1
}

# 3. Remove Edge Update services
$services = @("edgeupdate", "edgeupdatem")
foreach ($svc in $services) {
    Stop-Service $svc -Force -ErrorAction SilentlyContinue
    sc.exe delete $svc
}

# 4. Block reinstall using directory deny trick
$blockPaths = @(
  "$env:ProgramFiles (x86)\Microsoft\Edge",
  "$env:ProgramFiles\Microsoft\Edge"
)

foreach ($path in $blockPaths) {
    New-Item "$path" -ItemType File -Force > $null
    icacls "$path" /deny "NT AUTHORITY\SYSTEM:(F)" > $null
}

# 5. Block Edge Update folder hijack
$edgeUpdateBlock = "$env:ProgramFiles (x86)\Microsoft\EdgeUpdate"
New-Item "$edgeUpdateBlock" -ItemType File -Force > $null
icacls "$edgeUpdateBlock" /deny "NT AUTHORITY\SYSTEM:(F)" > $null

Write-Output ">> Microsoft Edge is DEAD. Gone. Vaporized. Fucker won’t rise again."
