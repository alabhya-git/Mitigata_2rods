param([int]$Port = 8765)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    $projectPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $projectPython)) {
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Virtual environment setup failed' }
        & $projectPython -m pip install -r requirements.lock
        if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
        & $projectPython -m pip install --no-deps -e .
        if ($LASTEXITCODE -ne 0) { throw 'Project installation failed' }
    }
    & $projectPython -m mitigata serve --demo --output runtime/live --port $Port
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
