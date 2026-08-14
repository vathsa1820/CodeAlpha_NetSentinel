# =============================================================================
# NetSentinel — Controlled Test Traffic Generator
# Phase 3 — Controlled Attack Simulation
#
# Usage:
#   .\tests\run_tests.ps1 -Test ICMP
#   .\tests\run_tests.ps1 -Test TCP
#   .\tests\run_tests.ps1 -Test HTTP
#   .\tests\run_tests.ps1 -Test All
# =============================================================================

param(
    [ValidateSet("ICMP", "TCP", "HTTP", "All")]
    [string]$Test = "All",
    [string]$TargetIP = "192.168.1.5",
    [int]$HttpPort = 8080,
    [int]$TcpPort  = 4444
)

Write-Host "================================================================="
Write-Host " NetSentinel - Controlled Attack Simulation Generator"
Write-Host " Target IP: $TargetIP"
Write-Host "================================================================="

function Run-Test1-ICMP {
    Write-Host '[TEST 1] Generating ICMP ping traffic to '$TargetIP'...' -ForegroundColor Cyan
    try {
        ping.exe -n 4 $TargetIP | Out-Null
        Write-Host '[TEST 1] ICMP ping sent successfully.' -ForegroundColor Green
    } catch {
        Write-Host '[TEST 1] ICMP ping failed.' -ForegroundColor Red
    }
}

function Run-Test2-TCP {
    Write-Host '[TEST 2] Generating TCP connection attempt to '$TargetIP':'$TcpPort'...' -ForegroundColor Cyan
    
    $listenerJob = Start-Job -ScriptBlock {
        param($port)
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port)
            $listener.Start()
            $client = $listener.AcceptTcpClient()
            $client.Close()
            $listener.Stop()
        } catch {}
    } -ArgumentList $TcpPort

    Start-Sleep -Milliseconds 500

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($TargetIP, $TcpPort, $null, $null)
        $success = $asyncResult.AsyncWaitHandle.WaitOne(2000, $false)
        if ($success) {
            $tcpClient.EndConnect($asyncResult)
            Write-Host '[TEST 2] TCP connection to port '$TcpPort' established.' -ForegroundColor Green
        } else {
            Write-Host '[TEST 2] TCP SYN packet sent to port '$TcpPort'.' -ForegroundColor Green
        }
        $tcpClient.Close()
    } catch {
        Write-Host '[TEST 2] TCP attempt completed.' -ForegroundColor Green
    } finally {
        Remove-Job -Job $listenerJob -Force -ErrorAction SilentlyContinue
    }
}

function Run-Test3-HTTP {
    Write-Host '[TEST 3] Generating HTTP request with URI test pattern netsentinel-test...' -ForegroundColor Cyan
    $url = "http://${TargetIP}:${HttpPort}/netsentinel-test"
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
        Write-Host '[TEST 3] HTTP GET request sent successfully to '$url -ForegroundColor Green
    } catch {
        Write-Host '[TEST 3] HTTP GET request sent to '$url -ForegroundColor Green
    }
}

switch ($Test) {
    "ICMP" { Run-Test1-ICMP }
    "TCP"  { Run-Test2-TCP }
    "HTTP" { Run-Test3-HTTP }
    "All"  {
        Run-Test1-ICMP
        Start-Sleep -Seconds 2
        Run-Test2-TCP
        Start-Sleep -Seconds 2
        Run-Test3-HTTP
    }
}

Write-Host "================================================================="
Write-Host " Simulation finished."
Write-Host "================================================================="
