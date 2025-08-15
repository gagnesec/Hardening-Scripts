#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Privacy & Security Hardening Script
.DESCRIPTION
    Applies privacy and security focused Group Policy settings via registry modifications.
    Based on recommended privacy and security best practices for Windows 10/11.
.NOTES
    Version: 1.0
    Author: Privacy & Security Configuration Script
    Requires: Administrator privileges
    Warning: Best applied on fresh Windows installations
#>

param(
    [switch]$SkipPrompts,
    [switch]$ForceEnterpriseSettings,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$script:changesMade = @()
$script:errors = @()

# Color functions for better UX
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$ForegroundColor = "White"
    )
    Write-Host $Message -ForegroundColor $ForegroundColor
}

function Write-Success { Write-ColorOutput -Message $args[0] -ForegroundColor Green }
function Write-Warning { Write-ColorOutput -Message $args[0] -ForegroundColor Yellow }
function Write-Error { Write-ColorOutput -Message $args[0] -ForegroundColor Red }
function Write-Info { Write-ColorOutput -Message $args[0] -ForegroundColor Cyan }

# Check if running as administrator
function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Detect Windows Edition
function Get-WindowsEditionType {
    try {
        $edition = Get-WindowsEdition -Online | Select-Object -ExpandProperty Edition
        Write-Info "Detected Windows Edition: $edition"
        
        if ($edition -match "Enterprise|Education") {
            return "Enterprise"
        } else {
            return "Pro"
        }
    }
    catch {
        Write-Warning "Could not detect Windows edition. Defaulting to Pro settings."
        return "Pro"
    }
}

# Check if BitLocker is enabled
function Test-BitLockerEnabled {
    try {
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        $osVolume = $bitlockerVolumes | Where-Object { $_.VolumeType -eq "OperatingSystem" }
        return ($osVolume -and $osVolume.ProtectionStatus -eq "On")
    }
    catch {
        return $false
    }
}

# Registry modification function with error handling
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [string]$Description
    )
    
    try {
        # Create registry path if it doesn't exist
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            if ($Verbose) { Write-Info "Created registry path: $Path" }
        }
        
        # Set the registry value
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        
        $script:changesMade += "$Description"
        if ($Verbose) { Write-Success "Applied: $Description" }
        
        return $true
    }
    catch {
        $script:errors += "Failed to apply: $Description - $_"
        Write-Error "Failed to apply: $Description"
        return $false
    }
}

# Main configuration function
function Start-PrivacyConfiguration {
    Write-ColorOutput "`n=== WINDOWS PRIVACY & SECURITY HARDENING SCRIPT ===" -ForegroundColor Magenta
    Write-ColorOutput "==================================================" -ForegroundColor Magenta
    
    # Warning for existing installations
    if (!$SkipPrompts) {
        Write-Warning "`nWARNING: This script is designed for fresh Windows installations."
        Write-Warning "Running on existing installations may cause unpredictable behavior."
        Write-Warning "It's recommended to create a system restore point before proceeding.`n"
        
        $continue = Read-Host "Do you want to continue? (Y/N)"
        if ($continue -ne 'Y' -and $continue -ne 'y') {
            Write-Info "Script cancelled by user."
            return
        }
    }
    
    # Detect Windows Edition
    $editionType = Get-WindowsEditionType
    if ($ForceEnterpriseSettings) {
        Write-Info "Forcing Enterprise edition settings as requested."
        $editionType = "Enterprise"
    }
    
    Write-Info "`nConfiguring for Windows $editionType Edition`n"
    
    # Check for user preferences
    $disableOneDrive = $true
    $enableVBS = $false
    
    if (!$SkipPrompts) {
        Write-ColorOutput "`n--- User Preferences ---" -ForegroundColor Yellow
        
        # OneDrive preference
        Write-Info "OneDrive will be disabled by default for privacy."
        $oneDriveResponse = Read-Host "Do you use OneDrive and want to keep it enabled? (Y/N)"
        if ($oneDriveResponse -eq 'Y' -or $oneDriveResponse -eq 'y') {
            $disableOneDrive = $false
            Write-Info "OneDrive will remain enabled."
        }
        
        # VBS preference
        Write-Info "`nVirtualization-Based Security (VBS) provides additional security but may impact performance."
        Write-Warning "Some older systems or virtualization software may have compatibility issues."
        $vbsResponse = Read-Host "Enable Virtualization-Based Security? (Y/N)"
        if ($vbsResponse -eq 'Y' -or $vbsResponse -eq 'y') {
            $enableVBS = $true
            Write-Info "VBS will be enabled."
        }
    }
    
    # Check BitLocker status
    if (Test-BitLockerEnabled) {
        Write-Warning "`nBitLocker is currently enabled on your system."
        Write-Warning "After applying these settings, you may want to re-encrypt your drive"
        Write-Warning "to ensure the new encryption settings take effect."
        if (!$SkipPrompts) {
            Read-Host "Press Enter to continue"
        }
    }
    
    Write-ColorOutput "`n--- Applying Privacy & Security Settings ---" -ForegroundColor Green
    
    # System > Device Guard
    if ($enableVBS) {
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
            -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord `
            -Description "Device Guard: Enable Virtualization Based Security"
        
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
            -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord `
            -Description "Device Guard: Secure Boot and DMA Protection"
        
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
            -Name "ConfigureSystemGuardLaunch" -Value 1 -Type DWord `
            -Description "Device Guard: Enable Secure Launch"
    }
    
    # System > Internet Communication Management
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" `
        -Name "CEIPEnable" -Value 0 -Type DWord `
        -Description "Turn off Windows Customer Experience Improvement Program"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" `
        -Name "Disabled" -Value 1 -Type DWord `
        -Description "Turn off Windows Error Reporting"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" `
        -Name "CEIP" -Value 2 -Type DWord `
        -Description "Turn off Windows Messenger Customer Experience Improvement Program"
    
    # System > OS Policies
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "AllowClipboardHistory" -Value 0 -Type DWord `
        -Description "Disable Clipboard History"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord `
        -Description "Disable Clipboard synchronization across devices"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "EnableActivityFeed" -Value 0 -Type DWord `
        -Description "Disable Activity Feed"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "PublishUserActivities" -Value 0 -Type DWord `
        -Description "Disable publishing of User Activities"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "UploadUserActivities" -Value 0 -Type DWord `
        -Description "Disable upload of User Activities"
    
    # System > User Profiles
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" `
        -Name "DisabledByGroupPolicy" -Value 1 -Type DWord `
        -Description "Turn off the advertising ID"
    
    # Windows Components > AutoPlay Policies
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord `
        -Description "Turn off AutoPlay for all drives"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord `
        -Description "Disallow AutoPlay for non-volume devices"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "NoAutorun" -Value 1 -Type DWord `
        -Description "Set default behavior for AutoRun: Do not execute"
    
    # Windows Components > BitLocker Drive Encryption
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
        -Name "EncryptionMethod" -Value 4 -Type DWord `
        -Description "BitLocker: Set encryption method to AES-256"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
        -Name "UseAdvancedStartup" -Value 1 -Type DWord `
        -Description "BitLocker: Allow additional authentication at startup"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
        -Name "UseTPMPIN" -Value 2 -Type DWord `
        -Description "BitLocker: Allow enhanced PINs for startup"
    
    # Windows Components > Cloud Content
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        -Name "DisableCloudOptimizedContent" -Value 1 -Type DWord `
        -Description "Turn off cloud optimized content"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord `
        -Description "Turn off cloud consumer account state content"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        -Name "DisableSoftLanding" -Value 1 -Type DWord `
        -Description "Do not show Windows tips"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord `
        -Description "Turn off Microsoft consumer experiences"
    
    # Windows Components > Credential User Interface
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" `
        -Name "EnableSecureCredentialPrompting" -Value 1 -Type DWord `
        -Description "Require trusted path for credential entry"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "NoLocalPasswordResetQuestions" -Value 1 -Type DWord `
        -Description "Prevent the use of security questions for local accounts"
    
    # Windows Components > Data Collection and Preview Builds
    if ($editionType -eq "Enterprise") {
        # Enterprise/Education can disable telemetry completely
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
            -Name "AllowTelemetry" -Value 0 -Type DWord `
            -Description "Diagnostic Data: Disabled (Enterprise/Education)"
        
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
            -Name "AllowDeviceNameInTelemetry" -Value 0 -Type DWord `
            -Description "Disable device name in telemetry"
    } else {
        # Pro Edition minimum is "Required diagnostic data" (value 1)
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
            -Name "AllowTelemetry" -Value 1 -Type DWord `
            -Description "Diagnostic Data: Required only (Pro Edition minimum)"
    }
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "LimitDiagnosticLogCollection" -Value 1 -Type DWord `
        -Description "Limit Diagnostic Log Collection"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "LimitDumpCollection" -Value 1 -Type DWord `
        -Description "Limit Dump Collection"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Value 0 -Type DWord `
        -Description "Disable Desktop Analytics collection"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord `
        -Description "Do not show feedback notifications"
    
    # Windows Components > File Explorer
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        -Name "DisableGraphRecentItems" -Value 1 -Type DWord `
        -Description "Turn off account-based insights and recent files in File Explorer"
    
    # Windows Components > MDM
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" `
        -Name "DisableRegistration" -Value 1 -Type DWord `
        -Description "Disable MDM Enrollment"
    
    # Windows Components > OneDrive
    if ($disableOneDrive) {
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" `
            -Name "DisableFileSyncNGSC" -Value 1 -Type DWord `
            -Description "Prevent the usage of OneDrive for file storage"
        
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" `
            -Name "DisableLibrariesDefaultSaveToOneDrive" -Value 1 -Type DWord `
            -Description "Save documents locally by default (not OneDrive)"
        
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" `
            -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord `
            -Description "Prevent OneDrive from generating network traffic until sign in"
    } else {
        Write-Info "Skipping OneDrive restrictions as per user preference"
    }
    
    # Windows Components > Push To Install
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" `
        -Name "DisablePushToInstall" -Value 1 -Type DWord `
        -Description "Turn off Push To Install service"
    
    # Windows Components > Search
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
        -Name "AllowCortana" -Value 0 -Type DWord `
        -Description "Disable Cortana"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
        -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord `
        -Description "Don't search the web or display web results in Search"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
        -Name "ConnectedSearchPrivacy" -Value 3 -Type DWord `
        -Description "Set search information sharing to Anonymous only"
    
    # Windows Components > Sync your settings
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" `
        -Name "DisableSettingSync" -Value 2 -Type DWord `
        -Description "Disable settings synchronization"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" `
        -Name "DisableSettingSyncUserOverride" -Value 1 -Type DWord `
        -Description "Prevent users from enabling sync"
    
    # Windows Components > Text input
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" `
        -Name "AllowLinguisticDataCollection" -Value 0 -Type DWord `
        -Description "Disable improve inking and typing recognition"
    
    # Windows Components > Windows Error Reporting > Consent
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" `
        -Name "DontSendAdditionalData" -Value 1 -Type DWord `
        -Description "Do not send additional error data"
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" `
        -Name "DefaultConsent" -Value 1 -Type DWord `
        -Description "Configure default consent: Always ask before sending data"
    
    Write-ColorOutput "`n--- Configuration Complete ---" -ForegroundColor Green
    
    # Summary
    Write-ColorOutput "`n=== SUMMARY ===" -ForegroundColor Cyan
    Write-Success "Successfully applied $($script:changesMade.Count) settings"
    
    if ($script:errors.Count -gt 0) {
        Write-Warning "`nThe following errors occurred:"
        foreach ($error in $script:errors) {
            Write-Error "  - $error"
        }
    }
    
    # Recommendations
    Write-ColorOutput "`n=== RECOMMENDATIONS ===" -ForegroundColor Yellow
    Write-Info "1. Restart your computer for all changes to take effect"
    
    if (Test-BitLockerEnabled) {
        Write-Info "2. Consider re-encrypting your BitLocker drive with the new settings"
    }
    
    Write-Info "3. Review the applied settings in Group Policy Editor (gpedit.msc) if available"
    Write-Info "4. Create a system restore point after verifying everything works correctly"
    
    if (!$SkipPrompts) {
        $restart = Read-Host "`nWould you like to restart your computer now? (Y/N)"
        if ($restart -eq 'Y' -or $restart -eq 'y') {
            Write-Warning "System will restart in 30 seconds. Save your work!"
            Start-Sleep -Seconds 30
            Restart-Computer -Force
        }
    }
}

# Main execution
try {
    if (-not (Test-Administrator)) {
        Write-Error "This script must be run as Administrator!"
        Write-Info "Please right-click and select 'Run as Administrator'"
        exit 1
    }
    
    Start-PrivacyConfiguration
}
catch {
    Write-Error "An unexpected error occurred: $_"
    exit 1
}
finally {
    if (!$SkipPrompts) {
        Write-Info "`nPress any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}
