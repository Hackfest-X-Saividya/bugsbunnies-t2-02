$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    $python = (Get-Command python -ErrorAction Stop).Source
}

Write-Host "Starting ZeroShadow backend on http://127.0.0.1:8000..."
function Test-BackendReady {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 2
        return $health.status -eq "ok"
    } catch {
        return $false
    }
}

if (-not (Test-BackendReady)) {
    $backendPort = Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
    if ($backendPort) {
        throw "Port 8000 is occupied, but the existing service did not pass /health. Inspect PID $($backendPort.OwningProcess) before starting another backend."
    }
    Start-Process -FilePath $python -ArgumentList "-m", "api_intelligence.http_api" -WorkingDirectory $root
    for ($attempt = 0; $attempt -lt 10 -and -not (Test-BackendReady); $attempt++) {
        Start-Sleep -Seconds 1
    }
    if (-not (Test-BackendReady)) {
        throw "The backend did not become ready. Check the Python environment and server output."
    }
} else {
    Write-Host "Backend is already healthy; reusing the existing process."
}

try {
    $frontendResponse = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:5173/" -TimeoutSec 2
    if ($frontendResponse.StatusCode -ge 200 -and $frontendResponse.StatusCode -lt 500) {
        Write-Host "Frontend is already responding on http://127.0.0.1:5173; reusing the existing process."
        exit 0
    }
} catch {
    $frontendPort = Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue
    if ($frontendPort) {
        throw "Port 5173 is occupied, but the existing service did not return an HTTP response. Inspect PID $($frontendPort.OwningProcess) before starting Vite."
    }
}

Write-Host "Backend is ready. Starting Vite on http://127.0.0.1:5173..."
Set-Location -LiteralPath $root
npm run dev -- --host 127.0.0.1
