param(
    [string]$RelayAddr = "103.135.147.226:8444",
    [string]$SshHost = "103.135.147.226",
    [int]$SshPort = 15042,
    [string]$RelayService = "chimney-relay.service",
    [string]$SocksAddr = "127.0.0.1:18081",
    [string]$SNI = "cloudflare.com",
    [string]$PSK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    [string]$URL = "http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin",
    [int]$Iterations = 3,
    [int]$IntervalSeconds = 3,
    [int]$CurlTimeoutSeconds = 180,
    [int64]$MaxClientPrivateMemoryGrowthBytes = 0,
    [int64]$MaxRelayMemoryGrowthBytes = 0,
    [string]$ReportPath = "",
    [switch]$StopClientWhenDone
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BinDir = Join-Path $Root "build\bin"
$WorkDir = Join-Path $Root "build\remote-download-soak"
$ClientExe = Join-Path $BinDir "chimney-client-windows-amd64.exe"
$ClientConfig = Join-Path $WorkDir "client.yaml"
$ClientOut = Join-Path $WorkDir "client.out.log"
$ClientErr = Join-Path $WorkDir "client.err.log"

if ($ReportPath -eq "") {
    $ReportPath = Join-Path $WorkDir "remote-download-soak-report.json"
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
        Start-Sleep -Milliseconds 250
    }
    throw "timeout waiting for $Address"
}

function Stop-Child([System.Diagnostics.Process]$Process) {
    if ($null -ne $Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(5000) | Out-Null
    }
}

function Measure-LocalProcessState([string]$Name, [System.Diagnostics.Process]$Process) {
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
        handle_count = [int]$fresh.HandleCount
        thread_count = [int]$fresh.Threads.Count
    }
}

function Measure-RemoteRelayState {
    $cmd = "systemctl show $RelayService -p MainPID -p MemoryCurrent --no-pager; systemctl is-active $RelayService"
    $lines = ssh -p $SshPort "root@$SshHost" $cmd
    $mainPid = $null
    $memory = $null
    $active = $false
    foreach ($line in $lines) {
        if ($line -like "MainPID=*") {
            $mainPid = [int64]($line.Substring("MainPID=".Length))
        }
        elseif ($line -like "MemoryCurrent=*") {
            $raw = $line.Substring("MemoryCurrent=".Length)
            if ($raw -match "^\d+$") {
                $memory = [int64]$raw
            }
        }
        elseif ($line -eq "active") {
            $active = $true
        }
    }
    return [ordered]@{
        name = "relay"
        service = $RelayService
        host = $SshHost
        pid = $mainPid
        alive = $active
        memory_current_bytes = $memory
    }
}

function Start-LocalClientIfNeeded {
    if (Test-TcpPort $SocksAddr 500) {
        Write-Step "using existing local SOCKS client on $SocksAddr"
        $hostName, $port = Split-HostPort $SocksAddr
        $conn = Get-NetTCPConnection -LocalAddress $hostName -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $conn -and $conn.OwningProcess -gt 0) {
            return Get-Process -Id $conn.OwningProcess -ErrorAction Stop
        }
        return $null
    }

    Write-Step "building and starting local chimney client on $SocksAddr"
    New-Item -ItemType Directory -Force -Path $BinDir, $WorkDir | Out-Null
    Push-Location $Root
    try {
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "0"
        go build -trimpath -ldflags="-s -w" -o $ClientExe .\cmd\chimney-client
    }
    finally {
        $env:GOOS = ""
        $env:GOARCH = ""
        $env:CGO_ENABLED = ""
        Pop-Location
    }

    @"
relay_addr: "$RelayAddr"
sni: "$SNI"
dest_addr: "127.0.0.1:1"
psk: "$PSK"
tag_len: 16
listen_addr: "$SocksAddr"
utls_fingerprint: "chrome"
connect_timeout: 10s
handshake_timeout: 10s
"@ | Set-Content -Encoding UTF8 -Path $ClientConfig

    Remove-Item $ClientOut, $ClientErr -ErrorAction SilentlyContinue
    $process = Start-Process -FilePath $ClientExe -ArgumentList @("-config", $ClientConfig) -WorkingDirectory $Root -RedirectStandardOutput $ClientOut -RedirectStandardError $ClientErr -PassThru -WindowStyle Hidden
    Wait-TcpPort $SocksAddr 30
    return $process
}

function Invoke-CurlDownload([int]$Iteration) {
    Write-Step "remote download iteration $Iteration/$Iterations"
    $args = @(
        "-x", "socks5h://$SocksAddr",
        "-L",
        "--max-time", "$CurlTimeoutSeconds",
        "-o", "NUL",
        "-w", "downloaded=%{size_download}`ntime_total=%{time_total}`nspeed_download=%{speed_download}`n",
        $URL
    )
    $output = & curl.exe @args 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "curl exited with code $LASTEXITCODE during iteration $Iteration"
    }
    $result = [ordered]@{}
    foreach ($line in $output) {
        if ($line -match "^([^=]+)=(.*)$") {
            $result[$Matches[1]] = $Matches[2]
        }
    }
    return [ordered]@{
        downloaded_bytes = [int64]$result["downloaded"]
        time_total_seconds = [double]$result["time_total"]
        speed_download_bytes_per_second = [double]$result["speed_download"]
    }
}

function Build-Trend([object[]]$Samples, [string]$Side, [string]$Field) {
    if ($Samples.Count -eq 0) {
        return $null
    }
    $values = @()
    foreach ($sample in $Samples) {
        $state = $sample.after.$Side
        if ($null -ne $state.$Field) {
            $values += [int64]$state.$Field
        }
    }
    if ($values.Count -eq 0) {
        return $null
    }
    return [ordered]@{
        first = $values[0]
        last = $values[$values.Count - 1]
        max = ($values | Measure-Object -Maximum).Maximum
        growth = $values[$values.Count - 1] - $values[0]
    }
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$clientProcess = $null
$startedClient = $false
$samples = New-Object System.Collections.Generic.List[object]
$startTime = Get-Date

try {
    $beforePort = Test-TcpPort $SocksAddr 500
    $clientProcess = Start-LocalClientIfNeeded
    $startedClient = -not $beforePort

    for ($i = 1; $i -le $Iterations; $i++) {
        $beforeClient = Measure-LocalProcessState "client" $clientProcess
        $beforeRelay = Measure-RemoteRelayState
        $download = Invoke-CurlDownload $i
        $afterClient = Measure-LocalProcessState "client" $clientProcess
        $afterRelay = Measure-RemoteRelayState

        $samples.Add([ordered]@{
            iteration = $i
            timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
            download = $download
            before = [ordered]@{
                client = $beforeClient
                relay = $beforeRelay
            }
            after = [ordered]@{
                client = $afterClient
                relay = $afterRelay
            }
        })

        if ($i -lt $Iterations -and $IntervalSeconds -gt 0) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    }

    $sampleArray = @($samples.ToArray())
    $clientPrivateTrend = Build-Trend $sampleArray "client" "private_memory_bytes"
    $relayMemoryTrend = Build-Trend $sampleArray "relay" "memory_current_bytes"

    $report = [ordered]@{
        started_at_utc = $startTime.ToUniversalTime().ToString("o")
        finished_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        relay_addr = $RelayAddr
        ssh_host = $SshHost
        ssh_port = $SshPort
        socks_addr = $SocksAddr
        url = $URL
        iterations = $Iterations
        started_client = $startedClient
        summary = [ordered]@{
            client_private_memory = $clientPrivateTrend
            relay_memory_current = $relayMemoryTrend
        }
        samples = $samples
    }

    $report | ConvertTo-Json -Depth 16 | Set-Content -Encoding UTF8 -Path $ReportPath
    Write-Step "client private memory growth: $($clientPrivateTrend.growth) bytes"
    Write-Step "relay memory growth: $($relayMemoryTrend.growth) bytes"

    if ($MaxClientPrivateMemoryGrowthBytes -gt 0 -and $clientPrivateTrend.growth -gt $MaxClientPrivateMemoryGrowthBytes) {
        throw "client private memory growth $($clientPrivateTrend.growth) exceeded threshold $MaxClientPrivateMemoryGrowthBytes"
    }
    if ($MaxRelayMemoryGrowthBytes -gt 0 -and $relayMemoryTrend.growth -gt $MaxRelayMemoryGrowthBytes) {
        throw "relay memory growth $($relayMemoryTrend.growth) exceeded threshold $MaxRelayMemoryGrowthBytes"
    }

    Write-Step "remote download soak passed; report: $ReportPath"
}
finally {
    if ($StopClientWhenDone -and $startedClient) {
        Stop-Child $clientProcess
    }
}
