# Run in an ELEVATED PowerShell ("Run as administrator") on every client PC.
# Tells you whether the PIM client will be able to read this PC's TPM identity.
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Administrator shell : $admin"
$tpm = Get-Tpm
Write-Host "TPM present         : $($tpm.TpmPresent)"
Write-Host "TPM ready           : $($tpm.TpmReady)"
Write-Host "Manufacturer        : $($tpm.ManufacturerIdTxt) $($tpm.ManufacturerVersion)"
if (-not $admin) { Write-Warning "Open PowerShell as Administrator, otherwise the endorsement key cannot be read."; exit 1 }
$ek = Get-TpmEndorsementKeyInfo -HashAlgorithm sha256
Write-Host "EK present          : $($ek.IsPresent)"
Write-Host "EK public key hash  : $($ek.PublicKeyHash)"
Write-Host "EK certificates     : $(@($ek.ManufacturerCertificates).Count) manufacturer, $(@($ek.AdditionalCertificates).Count) additional"
if ($ek.IsPresent) { Write-Host "`nOK - this PC can be used as a PIM client." -ForegroundColor Green } else { Write-Host "`nNo endorsement key. Enable the TPM (fTPM / PTT) in the BIOS." -ForegroundColor Red }
Write-Host "`nWindows Hello (PIN/fingerprint/face) must also be set up: Settings > Accounts > Sign-in options."
