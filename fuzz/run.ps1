<#
Restart loop for fuzz-runner on PowerShell (Windows). Mirrors run.sh.

Usage:  .\run.ps1 -Target <name> [-BudgetSec 30] [-Features dex,apk]

`-Features` is a comma list of fuzz-workspace cargo features
(dex|bytecode|apk|rebuild|resources|core|decompile|all); without it
every contract target reports SkippedDisabled.

Exit codes:
   0 = green (no panics within budget)
   1 = red   (one or more panics; see .\crashes\)
   2 = usage / setup error
#>

param(
    [Parameter(Mandatory = $true)][string]$Target,
    [int]$BudgetSec = 30,
    [string]$Features = $env:FEATURES
)

$ErrorActionPreference = 'Stop'

$LogDir       = "crashes"
$CorpusOutDir = "corpus-out/$Target"
$SeedsDir     = "seeds/$Target"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $CorpusOutDir | Out-Null

# Build first.
if ($Features) {
    cargo build --release --bin fuzz-runner --features $Features | Out-Null
} else {
    cargo build --release --bin fuzz-runner | Out-Null
}
if ($LASTEXITCODE -ne 0) { exit 2 }

$ErrorActionPreference = 'Stop'

$LogDir       = "crashes"
$CorpusOutDir = "corpus-out/$Target"
$SeedsDir     = "seeds/$Target"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $CorpusOutDir | Out-Null

$Bin = ".\target\release\fuzz-runner.exe"
if (-not (Test-Path $Bin)) {
    Write-Error "binary not found at $Bin"
    exit 2
}

$Start = Get-Date
$End   = $Start.AddSeconds($BudgetSec)
$Panics = 0
$Seed   = [uint64]0xA5A5C0DEBEEF

Write-Host "=== fuzz-runner restart loop ==="
while ((Get-Date) -lt $End) {
    $Remaining = ($End - (Get-Date)).TotalSeconds
    if ($Remaining -le 0) { break }

    & $Bin `
        --target $Target `
        --seconds ([int]$Remaining) `
        --seeds $SeedsDir `
        --corpus-out $CorpusOutDir `
        --crash-dir $LogDir `
        --seed $Seed
    $Exit = $LASTEXITCODE

    if ($Exit -eq 0) {
        Write-Host "fuzz-runner exited cleanly; stopping"
        break
    }

    $Panics++
    $Seed = $Seed + 1
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] exit=$Exit panic #$Panics; restarting"
}

Write-Host "=== summary ==="
Write-Host "target=$Target panics=$Panics budget=${BudgetSec}s"
if ($Panics -eq 0) {
    Write-Host "GREEN: no crashes within budget"
    exit 0
} else {
    Write-Host "RED: panics observed; see $LogDir\"
    exit 1
}
