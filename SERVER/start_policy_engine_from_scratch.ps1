<#
 FIDO2 PIM Chat - SERVER (identity provider + Policy Engine + chat API), from scratch.
 Send the whole SERVER folder to the server PC, open PowerShell inside it and run:

     .\start_policy_engine_from_scratch.ps1

 It checks Python, creates its own virtual environment, installs what it needs, opens the
 firewall port (when run as Administrator), prints the address the client PCs must use,
 and starts the server. The OTP codes ("SMS" and "Gmail") appear in this window.

 -Port 8000          port to listen on
 -RealTpmOnly        refuse simulated TPMs (use for the real demo)
 -ShowOtpInPages     also show the OTP codes inside the web pages (one-person testing)
 -Reset              delete the database first (start with no accounts)
#>
param(
    [int]$Port = 8000,
    [switch]$RealTpmOnly,
    [switch]$ShowOtpInPages,
    [switch]$Reset
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Fail($message) { Write-Host "`nERROR: $message" -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }

# 1) Python
$python = $null
foreach ($candidate in @('py', 'python')) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $python = $candidate; break }
}
if (-not $python) { Fail "Python 3.10+ is not installed. Install it from python.org and tick 'Add python.exe to PATH'." }
$pythonArguments = if ($python -eq 'py') { @('-3') } else { @() }

# 2) own virtual environment + packages
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    & $python @pythonArguments -m venv (Join-Path $PSScriptRoot ".venv")
    if ($LASTEXITCODE -ne 0) { Fail "Could not create the virtual environment." }
}
Write-Host "Checking packages..." -ForegroundColor Cyan
& $venvPython -m pip install --quiet --disable-pip-version-check -r (Join-Path $PSScriptRoot "server_requirements.txt")
if ($LASTEXITCODE -ne 0) { Fail "Package installation failed (is this PC online?)." }

# 3) optional reset
if ($Reset) {
    Get-ChildItem (Join-Path $PSScriptRoot "DATA") -Filter "*.sqlite3*" -ErrorAction SilentlyContinue | Remove-Item -Force
    Write-Host "Database cleared." -ForegroundColor Yellow
}

# 4) firewall (needs Administrator; skipped with a hint otherwise)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ruleName = "PIM server TCP $Port"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    if ($isAdmin) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
        Write-Host "Firewall: opened TCP $Port for the client PCs." -ForegroundColor Green
    } else {
        Write-Host "Firewall rule for TCP $Port not created (not Administrator). If clients cannot connect, re-run this script as Administrator." -ForegroundColor Yellow
    }
}

# 5) tell the operator what the clients must use
$addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress
Write-Host "`nClient PCs must start with one of these:" -ForegroundColor Cyan
foreach ($address in $addresses) { Write-Host "   .\start_client_from_scratch.ps1 -Server http://${address}:$Port" }

if ($RealTpmOnly) { $env:PIM_ALLOW_SIMULATED_TPM = "0" }
if ($ShowOtpInPages) { $env:PIM_DEMO_SHOW_OTP = "1" }

Write-Host "`nStarting the server (keep this window open; OTP codes appear here)`n" -ForegroundColor Cyan
& $venvPython run_server.py --host 0.0.0.0 --port $Port
if ($LASTEXITCODE -ne 0) { Fail "The server stopped with an error (see the message above)." }
