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

# Get Snort device index for the specified interface (-i flag)
$snortW = & $SNORT_EXE -W 2>&1
$ifIndex = $null
foreach ($line in $snortW) {
    if ($line -match "^\s*(\d+)\s+.*($Interface|192\.168|MediaTek)") {
        $ifIndex = [int]$matches[1]
        break
    }
}
if (-not $ifIndex) {
    $ifIndex = 1
}
Write-Host "[NetSentinel] Using Snort device interface index: $ifIndex"

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
