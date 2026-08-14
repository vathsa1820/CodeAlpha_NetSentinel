# =============================================================================
# NetSentinel — Snort Startup Script (Windows PowerShell)
# Phase 2 — Snort Configuration
#
# Usage:
#   Run as Administrator in PowerShell:
#   .\snort\config\start_snort.ps1
#
# Prerequisites:
#   - Snort 2.9.x installed to C:\Snort
#   - WinPcap or Npcap installed (required for live capture)
#   - Run as Administrator
# =============================================================================

param(
    [string]$Interface = "Wi-Fi",
    [switch]$TestMode  = $false
)

$SNORT_EXE  = "C:\Snort\bin\snort.exe"
$CONF_FILE  = "$PSScriptRoot\netsentinel.conf"
$LOG_DIR    = "C:\Snort\log"

# Ensure log directory exists
if (-not (Test-Path $LOG_DIR)) {
    New-Item -ItemType Directory -Path $LOG_DIR | Out-Null
    Write-Host "[NetSentinel] Created log directory: $LOG_DIR"
}

# Check Snort is installed
if (-not (Test-Path $SNORT_EXE)) {
    Write-Error "Snort not found at $SNORT_EXE. Please install Snort 2.9.x first."
    Write-Host "Download: https://www.snort.org/downloads"
    exit 1
}

# Get Windows interface index for Snort (-i flag)
$adapter = Get-NetAdapter -Name $Interface -ErrorAction SilentlyContinue
if (-not $adapter) {
    Write-Error "Network interface '$Interface' not found or not up."
    Write-Host "Available interfaces:"
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Format-Table Name, InterfaceDescription
    exit 1
}
$ifIndex = $adapter.InterfaceIndex
Write-Host "[NetSentinel] Using interface: $Interface (index $ifIndex)"

if ($TestMode) {
    # -T = test/validate configuration, then exit
    Write-Host "[NetSentinel] Running Snort in TEST mode (config validation only)..."
    & $SNORT_EXE -c $CONF_FILE -l $LOG_DIR -T
} else {
    # -A fast   = fast alert format
    # -l        = log directory
    # -i        = interface index
    # -c        = config file
    Write-Host "[NetSentinel] Starting Snort in live capture mode..."
    Write-Host "Press Ctrl+C to stop."
    & $SNORT_EXE -c $CONF_FILE -i $ifIndex -A fast -l $LOG_DIR
}
