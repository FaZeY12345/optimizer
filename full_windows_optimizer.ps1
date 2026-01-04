<# 
    Windows Performance & Privacy Optimizer
    --------------------------------------
    This script applies common performance, UI, and privacy tweaks
    to reduce background activity and improve responsiveness.

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

Write-Host "Applying system optimizations..." -ForegroundColor Green

# -------------------------------------------------
# Core performance services
# -------------------------------------------------

# Disable SysMain (Superfetch)
try {
    Stop-Service SysMain -ErrorAction SilentlyContinue
    Set-Service SysMain -StartupType Disabled
} catch {}

# Disable Windows Search indexing
try {
    Stop-Service WSearch -ErrorAction SilentlyContinue
    Set-Service WSearch -StartupType Disabled
} catch {}

# -------------------------------------------------
# Power & sleep behavior
# -------------------------------------------------

# Disable hibernation (also disables Fast Startup)
try {
    powercfg -h off | Out-Null
    powercfg -change -standby-timeout-ac 0
    powercfg -change -hibernate-timeout-ac 0
    powercfg -change -monitor-timeout-ac 0
} catch {}

# -------------------------------------------------
# Visual & UI responsiveness
# -------------------------------------------------

# Disable transparency
Set-ItemProperty `
    -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" `
    -Name "EnableTransparency" `
    -Type DWord `
    -Value 0 `
    -Force

# Disable animations and visual effects
Set-ItemProperty `
    -Path "HKCU:\Control Panel\Desktop" `
    -Name "UserPreferencesMask" `
    -Type Binary `
    -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) `
    -Force

# Disable window drag previews
Set-ItemProperty `
    -Path "HKCU:\Control Panel\Desktop" `
    -Name "DragFullWindows" `
    -Type String `
    -Value "0" `
    -Force

# -------------------------------------------------
# Notifications & background behavior
# -------------------------------------------------

# Disable toast notifications
Set-ItemProperty `
    -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" `
    -Name "ToastEnabled" `
    -Type DWord `
    -Value 0 `
    -Force

# Disable background apps (Store apps may lose functionality)
try {
    Get-AppxPackage | ForEach-Object {
        Add-AppxPackage `
            -Register "$($_.InstallLocation)\AppXManifest.xml" `
            -DisableDevelopmentMode `
            -ErrorAction SilentlyContinue
    }
} catch {}

# -------------------------------------------------
# Telemetry & data collection
# -------------------------------------------------

# Registry telemetry policy
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
    -Name "AllowTelemetry" `
    -Type DWord `
    -Value 0 `
    -Force

# Disable telemetry services
$telemetryServices = @(
    "DiagTrack",
    "dmwappushservice"
)

foreach ($service in $telemetryServices) {
    try {
        Stop-Service $service -ErrorAction SilentlyContinue
        Set-Service $service -StartupType Disabled
    } catch {}
}

# Disable CEIP
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" `
    -Name "CEIPEnable" `
    -Type DWord `
    -Value 0 `
    -Force

# -------------------------------------------------
# Advertising, tracking & personalization
# -------------------------------------------------

# Disable advertising ID
Set-ItemProperty `
    -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" `
    -Name "Enabled" `
    -Type DWord `
    -Value 0 `
    -Force

# Disable activity history / timeline
Set-ItemProperty `
    -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ActivityFeed" `
    -Name "PublishUserActivities" `
    -Type DWord `
    -Value 0 `
    -Force

# Disable system suggestions & ads
$cdm = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
Set-ItemProperty $cdm "SystemPaneSuggestionsEnabled" 0 -Type DWord -Force
Set-ItemProperty $cdm "SubscribedContent-338388Enabled" 0 -Type DWord -Force

# -------------------------------------------------
# Xbox & gaming background services
# -------------------------------------------------

$xboxServices = @(
    "XblAuthManager",
    "XblGameSave",
    "XboxGipSvc",
    "XboxNetApiSvc"
)

foreach ($service in $xboxServices) {
    try {
        Stop-Service $service -ErrorAction SilentlyContinue
        Set-Service $service -StartupType Disabled
    } catch {}
}

# Enable Game Mode
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\GameBar" `
    -Name "AllowAutoGameMode" `
    -Type DWord `
    -Value 1 `
    -Force

# -------------------------------------------------
# Windows Update (use with caution)
# -------------------------------------------------

try {
    Stop-Service wuauserv -ErrorAction SilentlyContinue
    Set-Service wuauserv -StartupType Disabled
} catch {}

# -------------------------------------------------
# Cleanup
# -------------------------------------------------

# Temporary files
$cleanupPaths = @(
    "$env:TEMP",
    "C:\Windows\Temp"
)

foreach ($path in $cleanupPaths) {
    try {
        Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
}

# Recycle Bin
try { Clear-RecycleBin -Force -ErrorAction SilentlyContinue } catch {}

Write-Host "Optimization complete. A restart is recommended." -ForegroundColor Green
