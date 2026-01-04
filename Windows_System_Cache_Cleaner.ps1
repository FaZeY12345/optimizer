<#
    Windows Cache Cleaner
    ---------------------
    Clears common system and application cache locations
    without touching personal files or critical system data.

    Requires Administrator privileges.
#>

# --- Admin check ---
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges are required."
    exit
}

Write-Host "Clearing system cache..." -ForegroundColor Green

# -------------------------------------------------
# Temp folders
# -------------------------------------------------

$cachePaths = @(
    "$env:TEMP",
    "C:\Windows\Temp"
)

foreach ($path in $cachePaths) {
    try {
        if (Test-Path $path) {
            Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

# -------------------------------------------------
# Windows Update cache
# -------------------------------------------------

try {
    Stop-Service wuauserv -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service wuauserv -ErrorAction SilentlyContinue
} catch {}

# -------------------------------------------------
# Delivery Optimization cache
# -------------------------------------------------

try {
    Stop-Service DoSvc -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\*" `
        -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service DoSvc -ErrorAction SilentlyContinue
} catch {}

# -------------------------------------------------
# Windows Error Reporting cache
# -------------------------------------------------

$werPaths = @(
    "C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
    "C:\ProgramData\Microsoft\Windows\WER\ReportQueue"
)

foreach ($path in $werPaths) {
    try {
        if (Test-Path $path) {
            Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

# -------------------------------------------------
# Prefetch (safe cleanup, not delete folder)
# -------------------------------------------------

try {
    Remove-Item "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
} catch {}

# -------------------------------------------------
# Recycle Bin
# -------------------------------------------------

try {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
} catch {}

Write-Host "System cache cleared successfully." -ForegroundColor Green
