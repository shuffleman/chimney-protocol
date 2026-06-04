param(
    [string]$RelayAddr = "127.0.0.1:18444",
    [string]$SocksAddr = "127.0.0.1:18080",
    [string]$SNI = "cloudflare.com",
    [string]$UserID = "550e8400-e29b-41d4-a716-446655440000",
    [int]$DownloadWorkers = 4,
    [int]$UploadWorkers = 4,
    [int64]$BytesPerWorker = 1048576,
    [int]$TimeoutSeconds = 60,
    [switch]$ReconnectCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RootUnix = $Root.Replace("\", "/")
$BinDir = Join-Path $Root "build\bin"
$WorkDir = Join-Path $Root "build\local-integration"
$RelayExe = Join-Path $BinDir "chimney-relay.exe"
$ClientExe = Join-Path $BinDir "chimney-client.exe"
$StressExe = Join-Path $BinDir "socks_stress.exe"
$RelayConfig = Join-Path $WorkDir "relay.yaml"
$ClientConfig = Join-Path $WorkDir "client.yaml"
$RelayOut = Join-Path $WorkDir "relay.out.log"
$RelayErr = Join-Path $WorkDir "relay.err.log"
$ClientOut = Join-Path $WorkDir "client.out.log"
$ClientErr = Join-Path $WorkDir "client.err.log"

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

function Run-Stress([string]$Label) {
    Write-Step "running mixed SOCKS5 traffic ($Label)"
    & $StressExe -socks $SocksAddr -dl $DownloadWorkers -ul $UploadWorkers -bytes $BytesPerWorker -timeout "$($TimeoutSeconds)s"
    if ($LASTEXITCODE -ne 0) {
        throw "socks_stress exited with code $LASTEXITCODE during $Label"
    }
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
try {
    $relay = Start-RelayProcess "initial"

    Write-Step "starting client SOCKS5 on $SocksAddr"
    $client = Start-Process -FilePath $ClientExe -ArgumentList @("-config", $ClientConfig) -WorkingDirectory $Root -RedirectStandardOutput $ClientOut -RedirectStandardError $ClientErr -PassThru -WindowStyle Hidden
    Wait-TcpPort $SocksAddr 15

    Run-Stress "initial"

    if ($ReconnectCheck) {
        Write-Step "stopping relay while keeping client alive"
        Stop-Child $relay
        $relay = $null
        Wait-TcpPortClosed $RelayAddr 15

        $relay = Start-RelayProcess "after restart"
        Start-Sleep -Milliseconds 500
        Run-Stress "after relay restart"
    }

    Write-Step "local binary integration test passed"
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
