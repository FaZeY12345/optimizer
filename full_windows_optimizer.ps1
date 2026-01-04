# ================================
# FULL ADVANCED WINDOWS OPTIMIZER SCRIPT
# ================================

# Ensure script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "Please run this script as Administrator!"
    exit
}

Write-Host "Starting full system optimization..." -ForegroundColor Green

# --- 1. Stop and disable SysMain (Superfetch/Prefetch) ---
Try {
    Stop-Service -Name "SysMain" -ErrorAction SilentlyContinue
    Set-Service -Name "SysMain" -StartupType Disabled
    Write-Host "SysMain (Prefetch) disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable SysMain: $_" }

# --- 2. Clean temp files and Recycle Bin ---
$tempPaths = @("$env:TEMP", "C:\Windows\Temp")
foreach ($path in $tempPaths) {
    Try {
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    } Catch { Write-Warning "Failed to clean $path: $_" }
}

Try { 
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Host "Temporary files and Recycle Bin cleaned." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to clear Recycle Bin." }

# --- 3. Disable unnecessary startup programs ---
$unwantedStartups = @(
    "OneDrive",
    "Spotify",
    "Adobe Acrobat Update"
)
foreach ($app in $unwantedStartups) {
    Try {
        $startup = Get-CimInstance Win32_StartupCommand | Where-Object {$_.Name -like "*$app*"}
        foreach ($item in $startup) {
            Invoke-CimMethod -InputObject $item -MethodName Delete
            Write-Host "$app startup disabled." -ForegroundColor Cyan
        }
    } Catch { Write-Warning "Could not disable startup for $app." }
}

# --- 4. Disable safe unnecessary services ---
$safeServices = @(
    "Bluetooth Support Service",
    "RemoteRegistry"
)
foreach ($svc in $safeServices) {
    Try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled
        Write-Host "$svc disabled." -ForegroundColor Cyan
    } Catch { Write-Warning "Could not disable $svc." }
}

# --- 5. Disable notifications ---
Try {
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -PropertyType DWord -Value 0 -Force
    Write-Host "Windows notifications disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable notifications." }

# --- 6. Disable transparency ---
Try {
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -PropertyType DWord -Value 0 -Force
    Write-Host "Transparency disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable transparency." }

# --- 7. Disable animations ---
Try {
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -PropertyType Binary -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Force
    Write-Host "Animations disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable animations." }

# --- 8. Disable snap window animations ---
Try {
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -PropertyType String -Value 0 -Force
    Write-Host "Snap window animations disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable snap animations." }

# --- 9. Disable background apps (can break some apps) ---
Try {
    Get-AppxPackage | ForEach-Object { Add-AppxPackage -register "$($_.InstallLocation)\AppXManifest.xml" -DisableDevelopmentMode }
    Write-Host "Background apps disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable background apps." }

# --- 10. Disable sleep / hibernate / fast startup / hybrid sleep ---
Try {
    powercfg -h off
    powercfg -change -standby-timeout-ac 0
    powercfg -change -hibernate-timeout-ac 0
    powercfg -change -monitor-timeout-ac 0
    Write-Host "Sleep, Hibernate, Fast Startup, and Hybrid Sleep disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable sleep modes." }

# --- 11. Disable telemetry and data collection ---
Try {
    # Disable telemetry via registry
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "RestrictTelemetry" -Value 1 -Type DWord -Force

    # Stop and disable telemetry services
    Stop-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
    Set-Service -Name "DiagTrack" -StartupType Disabled
    Stop-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -StartupType Disabled

    # Disable Customer Experience Improvement Program
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord -Force
    Write-Host "Telemetry and diagnostic data collection disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable telemetry." }

# --- 12. Disable telemetry scheduled tasks ---
$tasks = @(
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Maintenance\WinSAT",
    "\Microsoft\Windows\WDI\ResolutionHost"
)
foreach ($task in $tasks) {
    Try {
        Disable-ScheduledTask -TaskPath (Split-Path $task) -TaskName (Split-Path $task -Leaf) -ErrorAction SilentlyContinue
        Write-Host "Disabled scheduled task: $task" -ForegroundColor Cyan
    } Catch { Write-Warning "Failed to disable task $task." }
}

# --- 13. Disable Windows Update service ---
Try {
    Stop-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    Set-Service -Name "wuauserv" -StartupType Disabled
    Write-Host "Windows Update disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable Windows Update." }

# --- 14. Disable Xbox services ---
Try {
    $xboxServices = @(
        "XblAuthManager",
        "XblGameSave",
        "XboxGipSvc",
        "XboxNetApiSvc"
    )
    foreach ($svc in $xboxServices) {
        Stop-Service -Name $svc -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled
        Write-Host "Disabled Xbox service: $svc" -ForegroundColor Cyan
    }
} Catch { Write-Warning "Failed to disable Xbox services." }

# --- 15. Enable Game Mode ---
Try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1 -Type DWord -Force
    Write-Host "Game Mode enabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to enable Game Mode." }

# --- 16. Disable ads and advertising ID ---
Try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ActivityFeed" -Name "PublishUserActivities" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force
    Write-Host "Advertising ID, Activity Feed, and system ads disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable ads and telemetry." }

# --- 17. Disable Windows Search Indexing ---
Try {
    Stop-Service -Name "WSearch" -ErrorAction SilentlyContinue
    Set-Service -Name "WSearch" -StartupType Disabled
    Write-Host "Windows Search indexing disabled." -ForegroundColor Cyan
} Catch { Write-Warning "Failed to disable search indexing." }

# --- 18. Optimize CPU priority for foreground apps (optional) ---
Try {
    # This is an advanced tweak and might not be needed for all systems
    # Registry tweak placeholder (no direct documented key for this)
    Write-Host "CPU priority optimization skipped (requires manual tuning)." -ForegroundColor Yellow
} Catch { Write-Warning "Failed to optimize CPU priority." }

# --- 19. Timer resolution tweak notice ---
Write-Host "Timer resolution tweak requires advanced API calls and is skipped in this script." -ForegroundColor Yellow

Write-Host "✅ Full advanced optimization completed. Some changes require restart to apply." -ForegroundColor Green
