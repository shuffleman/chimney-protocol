param(
    [string]$RelayAddr = "127.0.0.1:18444",
    [string]$SocksAddr = "127.0.0.1:18080",
    [string]$SNI = "cloudflare.com",
    [string]$UserID = "550e8400-e29b-41d4-a716-446655440000",
    [int]$DownloadWorkers = 8,
    [int]$UploadWorkers = 8,
    [int64]$BytesPerWorker = 8388608,
    [int]$Iterations = 10,
    [int]$IntervalSeconds = 2,
    [int]$StressTimeoutSeconds = 180,
    [string]$ReportPath = "",
    [switch]$ReconnectHalfway
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RootUnix = $Root.Replace("\", "/")
$BinDir = Join-Path $Root "build\bin"
$WorkDir = Join-Path $Root "build\local-soak"
$RelayExe = Join-Path $BinDir "chimney-relay.exe"
$ClientExe = Join-Path $BinDir "chimney-client.exe"
$StressExe = Join-Path $BinDir "socks_stress.exe"
$RelayConfig = Join-Path $WorkDir "relay.yaml"
$ClientConfig = Join-Path $WorkDir "client.yaml"
$RelayOut = Join-Path $WorkDir "relay.out.log"
$RelayErr = Join-Path $WorkDir "relay.err.log"
$ClientOut = Join-Path $WorkDir "client.out.log"
$ClientErr = Join-Path $WorkDir "client.err.log"

if ($ReportPath -eq "") {
    $ReportPath = Join-Path $WorkDir "soak-report.json"
}

function Write-Step([string]$Message) {
    Write-Host "==> $Message"
}

function Split-HostPort([string]$Address) {
    $parts = $Address.Split(":")
    if ($parts.Length -lt 2) {
        throw "invalid host:port address: $Address"
    }
    $port = [int]$parts[$parts.Length - 1]
    $hostName = ($parts[0..($parts.Length - 2)] -join ":").Trim("[", "]")
    if ($hostName -eq "" -or $hostName -eq "0.0.0.0") {
        $hostName = "127.0.0.1"
    }
    return @($hostName, $port)
}

function Test-TcpPort([string]$Address, [int]$TimeoutMs = 250) {
    $hostName, $port = Split-HostPort $Address
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($hostName, $port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.EndConnect($iar)
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Wait-TcpPort([string]$Address, [int]$TimeoutSec) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-TcpPort $Address 250) {
            return
        }
        Start-Sleep -Milliseconds 200
    }
    throw "timeout waiting for $Address"
}

function Wait-TcpPortClosed([string]$Address, [int]$TimeoutSec) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-TcpPort $Address 250)) {
            return
        }
        Start-Sleep -Milliseconds 200
    }
    throw "timeout waiting for $Address to close"
}

function Stop-Child([System.Diagnostics.Process]$Process) {
    if ($null -ne $Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(5000) | Out-Null
    }
}

function Start-RelayProcess([string]$Label) {
    Write-Step "starting relay on $RelayAddr ($Label)"
    $process = Start-Process -FilePath $RelayExe -ArgumentList @("-config", $RelayConfig) -WorkingDirectory $Root -RedirectStandardOutput $RelayOut -RedirectStandardError $RelayErr -PassThru -WindowStyle Hidden
    Wait-TcpPort $RelayAddr 15
    return $process
}

function Measure-ProcessState([string]$Name, [System.Diagnostics.Process]$Process) {
    if ($null -eq $Process -or $Process.HasExited) {
        return [ordered]@{
            name = $Name
            pid = $null
            alive = $false
        }
    }

    $fresh = Get-Process -Id $Process.Id -ErrorAction Stop
    return [ordered]@{
        name = $Name
        pid = $fresh.Id
        alive = $true
        working_set_bytes = [int64]$fresh.WorkingSet64
        private_memory_bytes = [int64]$fresh.PrivateMemorySize64
        virtual_memory_bytes = [int64]$fresh.VirtualMemorySize64
        handle_count = [int]$fresh.HandleCount
        thread_count = [int]$fresh.Threads.Count
    }
}

function Run-StressJson([int]$Iteration) {
    $stressPath = Join-Path $WorkDir ("stress-{0:D3}.json" -f $Iteration)
    Write-Step "running mixed SOCKS5 traffic iteration $Iteration/$Iterations"
    & $StressExe -socks $SocksAddr -dl $DownloadWorkers -ul $UploadWorkers -bytes $BytesPerWorker -timeout "$($StressTimeoutSeconds)s" -json | Tee-Object -FilePath $stressPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "socks_stress exited with code $LASTEXITCODE during iteration $Iteration"
    }
    return (Get-Content $stressPath -Raw | ConvertFrom-Json)
}

New-Item -ItemType Directory -Force -Path $BinDir, $WorkDir | Out-Null

if (Test-TcpPort $RelayAddr) {
    throw "relay address is already in use before test: $RelayAddr"
}
if (Test-TcpPort $SocksAddr) {
    throw "SOCKS address is already in use before test: $SocksAddr"
}

Write-Step "building relay, client, and socks_stress binaries"
Push-Location $Root
try {
    go build -o $RelayExe .\cmd\chimney-relay
    go build -o $ClientExe .\cmd\chimney-client
    go build -o $StressExe .\cmd\socks_stress
}
finally {
    Pop-Location
}

@"
listen_addr: "$RelayAddr"
tag_len: 16
user_ids:
  - "$UserID"
intent_file: "$RootUnix/config/intent.yaml"
enforce_file: "$RootUnix/config/enforce.yaml"
cloud_region: "us-east-1"
default_backend: ""
handshake_timeout: 10s
auth_read_timeout: 5s
enable_profiling: false
log_level: "info"
connect_deny_private: false
"@ | Set-Content -Encoding UTF8 -Path $RelayConfig

@"
relay_addr: "$RelayAddr"
sni: "$SNI"
dest_addr: "127.0.0.1:1"
user_id: "$UserID"
tag_len: 16
listen_addr: "$SocksAddr"
utls_fingerprint: "chrome"
connect_timeout: 10s
handshake_timeout: 10s
"@ | Set-Content -Encoding UTF8 -Path $ClientConfig

$relay = $null
$client = $null
$samples = New-Object System.Collections.Generic.List[object]
$startTime = Get-Date

try {
    $relay = Start-RelayProcess "initial"

    Write-Step "starting client SOCKS5 on $SocksAddr"
    $client = Start-Process -FilePath $ClientExe -ArgumentList @("-config", $ClientConfig) -WorkingDirectory $Root -RedirectStandardOutput $ClientOut -RedirectStandardError $ClientErr -PassThru -WindowStyle Hidden
    Wait-TcpPort $SocksAddr 15

    for ($i = 1; $i -le $Iterations; $i++) {
        if ($ReconnectHalfway -and $i -eq ([int][Math]::Floor($Iterations / 2) + 1)) {
            Write-Step "restarting relay halfway while keeping client alive"
            Stop-Child $relay
            $relay = $null
            Wait-TcpPortClosed $RelayAddr 15
            $relay = Start-RelayProcess "halfway restart"
            Start-Sleep -Milliseconds 500
        }

        $beforeClient = Measure-ProcessState "client" $client
        $beforeRelay = Measure-ProcessState "relay" $relay
        $stress = Run-StressJson $i
        $afterClient = Measure-ProcessState "client" $client
        $afterRelay = Measure-ProcessState "relay" $relay

        $samples.Add([ordered]@{
            iteration = $i
            timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
            stress = $stress
            before = @($beforeClient, $beforeRelay)
            after = @($afterClient, $afterRelay)
        })

        if ($i -lt $Iterations -and $IntervalSeconds -gt 0) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    }

    $report = [ordered]@{
        started_at_utc = $startTime.ToUniversalTime().ToString("o")
        finished_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        relay_addr = $RelayAddr
        socks_addr = $SocksAddr
        download_workers = $DownloadWorkers
        upload_workers = $UploadWorkers
        bytes_per_worker = $BytesPerWorker
        iterations = $Iterations
        reconnect_halfway = [bool]$ReconnectHalfway
        samples = $samples
    }

    $report | ConvertTo-Json -Depth 16 | Set-Content -Encoding UTF8 -Path $ReportPath
    Write-Step "local soak test passed; report: $ReportPath"
}
catch {
    Write-Host ""
    Write-Host "relay stdout tail:"
    if (Test-Path $RelayOut) { Get-Content $RelayOut -Tail 40 }
    Write-Host ""
    Write-Host "relay stderr tail:"
    if (Test-Path $RelayErr) { Get-Content $RelayErr -Tail 40 }
    Write-Host ""
    Write-Host "client stdout tail:"
    if (Test-Path $ClientOut) { Get-Content $ClientOut -Tail 40 }
    Write-Host ""
    Write-Host "client stderr tail:"
    if (Test-Path $ClientErr) { Get-Content $ClientErr -Tail 40 }
    throw
}
finally {
    Stop-Child $client
    Stop-Child $relay
}
