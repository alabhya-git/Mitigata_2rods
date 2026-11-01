param([int]$Seed = 607)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    docker compose up --build -d
    if ($LASTEXITCODE -ne 0) { throw 'Container startup failed' }
    docker compose exec -T gateway nginx -s reload
    if ($LASTEXITCODE -ne 0) { throw 'Gateway configuration reload failed' }
    $deadline = (Get-Date).AddSeconds(120)
    $captureRoot = $null
    while ((Get-Date) -lt $deadline) {
        $latest = Join-Path $projectRoot 'runtime\capture\latest.json'
        if (Test-Path -LiteralPath $latest) {
            $sessionInfo = Get-Content -LiteralPath $latest -Raw | ConvertFrom-Json
            $captureRoot = Join-Path (Join-Path $projectRoot 'runtime\capture') $sessionInfo.session
            $captureLog = Join-Path $captureRoot 'tcpdump.log'
            $metadataPath = Join-Path $captureRoot 'observer.json'
            if ((Test-Path -LiteralPath $captureLog) -and (Test-Path -LiteralPath $metadataPath)) {
                $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
                if (-not $metadata.ended -and (Get-Content -LiteralPath $captureLog -Raw) -match 'listening on any') { break }
            }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $captureRoot -or (Get-Date) -ge $deadline) { throw 'Independent observer did not become ready' }
    $gatewayReady = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri 'http://127.0.0.1:8766/health' -TimeoutSec 3
            if ($health.status -eq 'ok') { $gatewayReady = $true; break }
        } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $gatewayReady) { throw 'Local control gateway did not become ready' }
    $tokenPath = Join-Path $projectRoot 'runtime\container\operator-token.txt'
    $operatorToken = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
    $headers = @{ Authorization = "Bearer $operatorToken" }
    $body = @{ seed = $Seed; layout = 'json' } | ConvertTo-Json
    $created = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8766/api/demo' -Headers $headers -ContentType 'application/json' -Body $body
    $runId = $created.run_id
    $deadline = (Get-Date).AddSeconds(120)
    do {
        Start-Sleep -Seconds 1
        $runReport = Invoke-RestMethod -Uri "http://127.0.0.1:8766/api/runs/$runId" -Headers $headers
    } while ($runReport.run.status -eq 'running' -and (Get-Date) -lt $deadline)
    docker compose stop observer
    if ($runReport.run.status -ne 'completed') { throw "Container assessment did not complete: $($runReport.run.status)" }
    $engineContainer = docker compose ps -q engine
    $inspection = docker inspect $engineContainer | ConvertFrom-Json
    $sourceAddresses = @('127.0.0.1', '::1') + @($inspection.NetworkSettings.Networks.PSObject.Properties | ForEach-Object { $_.Value.IPAddress } | Where-Object { $_ })
    $captureSession = $sessionInfo.session
    $observeArgs = @('-T','engine','python','-m','mitigata','observe',$runId,'--root','/data','--capture',"/capture/$captureSession/assessment.pcap",'--metadata',"/capture/$captureSession/observer.json",'--log',"/capture/$captureSession/tcpdump.log",'--infrastructure','127.0.0.1:8765')
    foreach ($sourceAddress in $sourceAddresses) { $observeArgs += @('--source-address', $sourceAddress) }
    docker compose exec @observeArgs
    if ($LASTEXITCODE -ne 0) { throw 'Independent capture measurement failed or was inconclusive' }
    Write-Output "Validated container run: $runId"
    Write-Output "Dashboard: http://127.0.0.1:8766/"
} finally {
    Pop-Location
}
