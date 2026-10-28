$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    $python = (Get-Command python -ErrorAction Stop).Source
}

Write-Host "Starting ZeroShadow backend on http://127.0.0.1:8000..."
Start-Process -FilePath $python -ArgumentList "-m", "api_intelligence.http_api" -WorkingDirectory $root

Start-Sleep -Seconds 2
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 5
    if ($health.status -ne "ok") {
        throw "The backend health check returned an unexpected response."
    }
} catch {
    throw "The backend did not become ready. Check the Python environment and server output. $($_.Exception.Message)"
}

Write-Host "Backend is ready. Starting Vite on http://127.0.0.1:5173..."
Set-Location -LiteralPath $root
npm run dev -- --host 127.0.0.1
