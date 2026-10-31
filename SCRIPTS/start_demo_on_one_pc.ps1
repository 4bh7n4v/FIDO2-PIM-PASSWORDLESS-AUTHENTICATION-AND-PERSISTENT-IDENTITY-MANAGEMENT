# Whole system on ONE PC for a quick try-out (no TPM needed): a server and two simulated client PCs.
$project = Split-Path -Parent $PSScriptRoot
$python = "$project\.venv\Scripts\python.exe"
$env:PIM_DEMO_SHOW_OTP = "1"
Start-Process $python -ArgumentList "`"$project\SERVER\run_server.py`" --host 127.0.0.1 --port 8000"
Start-Sleep -Seconds 3
Start-Process $python -ArgumentList "`"$project\CLIENT\run_client.py`" --server http://localhost:8000 --tpm simulated --tpm-name PC-1 --port 8765"
Start-Process $python -ArgumentList "`"$project\CLIENT\run_client.py`" --server http://localhost:8000 --tpm simulated --tpm-name PC-2 --port 8766"
Write-Host "Server on :8000, USER1 page http://localhost:8765, USER2 page http://localhost:8766"
Write-Host "(Windows Hello still asks for your PIN/fingerprint; with both pages on one PC the TPM name decides which 'PC' each is.)"
