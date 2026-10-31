<#
 FIDO2 PIM Chat - CLIENT, from scratch.
 Send the whole CLIENT folder to a user PC, open PowerShell inside it and run:

     .\start_client_from_scratch.ps1 -Server http://192.168.43.10:8000

 It checks Python, creates its own virtual environment, installs what it needs, asks for
 Administrator rights (Windows requires them to read the TPM), checks that the server can be
 reached, reads this PC's TPM and opens the chat page on http://localhost:8765.

 -Port 8765          local port of the chat page (8765-8780)
 -Simulated          no TPM on this PC: use a fake one (demo only)
 -TpmName PC-1       name of the fake TPM when -Simulated is used
#>
param(
    [string]$Server,
    [int]$Port = 8765,
    [switch]$Simulated,
    [string]$TpmName = "PC-1"
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Fail($message) { Write-Host "`nERROR: $message" -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }

if (-not $Server) { $Server = Read-Host "Address of the PIM server (for example http://192.168.43.10:8000)" }
if ($Server -notmatch '^https?://') { $Server = "http://$Server" }
$Server = $Server.TrimEnd('/')

# 1) Administrator rights are needed to read the TPM endorsement key
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $Simulated) {
    Write-Host "Restarting as Administrator (needed to read the TPM)..." -ForegroundColor Yellow
    $arguments = "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Server `"$Server`" -Port $Port"
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit 0
}

# 2) Python
$python = $null
foreach ($candidate in @('py', 'python')) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $python = $candidate; break }
}
if (-not $python) { Fail "Python 3.10+ is not installed. Install it from python.org and tick 'Add python.exe to PATH'." }
$pythonArguments = if ($python -eq 'py') { @('-3') } else { @() }

# 3) own virtual environment + packages
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    & $python @pythonArguments -m venv (Join-Path $PSScriptRoot ".venv")
    if ($LASTEXITCODE -ne 0) { Fail "Could not create the virtual environment." }
}
Write-Host "Checking packages..." -ForegroundColor Cyan
& $venvPython -m pip install --quiet --disable-pip-version-check -r (Join-Path $PSScriptRoot "client_requirements.txt")
if ($LASTEXITCODE -ne 0) { Fail "Package installation failed (is this PC online?)." }

# 4) can we reach the server?
try {
    $health = Invoke-RestMethod -Uri "$Server/health" -TimeoutSec 5
    Write-Host "Server reachable: $Server" -ForegroundColor Green
} catch {
    Write-Host "`nThe PIM server at $Server is NOT reachable." -ForegroundColor Red
    Write-Host " - Is the server script running on the server PC?"
    Write-Host " - Same Wi-Fi / hotspot? Right IP address? Firewall on the server PC (TCP 8000)?"
    if ((Read-Host "Start anyway? (y/N)") -ne 'y') { exit 1 }
}

# 5) TPM / Windows Hello hints, then start
if (-not $Simulated) {
    Write-Host "Reminder: Windows Hello (PIN / fingerprint / face) must be set up: Settings > Accounts > Sign-in options." -ForegroundColor DarkGray
}
$clientArguments = @("run_client.py", "--server", $Server, "--port", $Port)
if ($Simulated) { $clientArguments += @("--tpm", "simulated", "--tpm-name", $TpmName) } else { $clientArguments += @("--tpm", "real") }
Write-Host "`nStarting the client agent. Chat page: http://localhost:$Port  (keep this window open)`n" -ForegroundColor Cyan
& $venvPython @clientArguments
if ($LASTEXITCODE -ne 0) { Fail "The client stopped with an error (see the message above)." }
