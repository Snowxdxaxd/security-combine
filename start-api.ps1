param(
    [string]$BindAddress = "127.0.0.1",
    [int]$Port = 8080,
    [switch]$SkipBootstrap
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $ProjectRoot ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$ReqFile = Join-Path $ProjectRoot "requirements.txt"

Set-Location $ProjectRoot

if (-not (Test-Path $VenvPython)) {
    Write-Host "Creating virtual environment in .venv ..."
    python -m venv $VenvDir
}

if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment python was not created: $VenvPython"
}

if (-not $SkipBootstrap) {
    Write-Host "Installing python dependencies from requirements.txt ..."
    & $VenvPython -m pip install -r $ReqFile
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "Installing Playwright Chromium ..."
    & $VenvPython -m playwright install chromium
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "Starting API on http://$BindAddress`:$Port using $VenvPython"
& $VenvPython -m uvicorn app.main:app --host $BindAddress --port $Port
