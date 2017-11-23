<#

.SYNOPSIS
    Script to help install Windows Subsystem for Linux.

.DESCRIPTION
    An automated method of installing WSL.

.PARAMETER Confirm
    Whether to prompt for confirmation of actions

.PARAMETER Force
    Whether to force actions e.g. rebooting computer

.PARAMETER RunAs
    Attempt to self-elevate if not specified assumes that the PowerShell session is already elevated.

.EXAMPLE
    Install Windows Subsystem for Linux enabling self-elevation and automatically restart without prompting.
                                                                                                    
    Enable-WindowsSubsystemLinux -Force -RunAs

.NOTES
    Author: Tony Skidmore @tonyskidmore
    Initial Creation Date: 22nd Oct 2017
    Version: 0.0.1

.LINK
    https://msdn.microsoft.com/en-gb/commandline/wsl/install_guide

#>

[CmdletBinding()]
Param
(

    [switch]
    $Force,

    [switch]
    $RunAs,

    [switch]
    $CheckMode

)

#region functions

function Enable-WSLFeature()
{
    try {
        $feature = Enable-WindowsOptionalFeature -FeatureName Microsoft-Windows-Subsystem-Linux -Online -ErrorAction Stop
    }
    catch {
        Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : $($_.Exception.Message)"
        throw $_
    }

    $feature
}

function Test-WSLInstalled()
{
    if(-not (Test-RunAs)) {
        Write-Output "Error: Checking for Microsoft-Windows-Subsystem-Linux feature requires elevation."        
    } 
    else {
        try {
            $feature = Get-WindowsOptionalFeature -FeatureName Microsoft-Windows-Subsystem-Linux -Online -ErrorAction Stop
        }
        catch {
            Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : $($_.Exception.Message)"
            throw $_
        }
    }

    if($feature.State -eq 'Enabled') {
        $true
    } else {
        $false
    }

}


function Test-RunAs()
{
    # https://stackoverflow.com/questions/40207676/self-elevating-script-execution-policy

    # Get the ID and security principal of the current user account
    $myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent();
    $myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)

    # Get the security principal for the administrator role
    $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

    # Check to see if we are currently running as an administrator
    if ($myWindowsPrincipal.IsInRole($adminRole)) {
        Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : Session is elevated"
        $true        
    } else {
        Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : Session is not elevated"
        $false
    }
} # function Test-RunAs


function Enable-RunAs()
{
    # https://blogs.msdn.microsoft.com/virtual_pc_guy/2010/09/23/a-self-elevating-powershell-script/
    # https://www.autoitscript.com/forum/topic/174609-powershell-script-to-self-elevate/

    if(-not (Test-RunAs)) {
        Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : Attempting to self-elevate"

        $scriptPath = $script:MyInvocation.MyCommand.Path

        [string[]]$argList = @('-ExecutionPolicy RemoteSigned', '-File', $scriptPath)
        $boundParams = $script:MyInvocation.BoundParameters.GetEnumerator() 

        foreach($param in $boundParams) {
            if(($param.Value).IsPresent) {
                $argList += "-$($param.Key)"
            } else {
                $argList += "-$($param.Key)", "$($param.Value)"
            }
        }


        $params = @{
            'PassThru' = $true
            'Verb' = 'RunAs'
            'Wait' = $true
            'WorkingDirectory' = $pwd
            'ArgumentList' = $argList
        }

        try
        {    
            # $process = Start-Process PowerShell.exe -PassThru -Verb Runas -Wait -WorkingDirectory $pwd -ArgumentList $argList
            $process = Start-Process PowerShell.exe @params
            Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : ExitCode : $($process.ExitCode)"
        }
        catch {
            Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : $($_.Exception.Message)"
            throw $_
        }

    }
} # function Enable-RunAs

function Get-DeveloperMode() {
    #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
    $value = (Get-ItemProperty -Path $key -Name AllowDevelopmentWithoutDevLicense -ErrorAction SilentlyContinue).AllowDevelopmentWithoutDevLicense

    if($value -eq 1) {
        $true
    } else {
        $false
    }

} # function Get-DeveloperMode

function Enable-DeveloperMode() {
    #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
    $registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
    $name = 'AllowDevelopmentWithoutDevLicense'
    $value = 1

    if(!(Test-Path $registryPath)) {

        try {
            New-Item -Path $registryPath -Force -ErrorAction Stop| Out-Null
            $newKey = New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force -ErrorAction Stop
        }
        catch [System.Security.SecurityException] {
            Write-Output "Error: Security exception.  You need to run this script as administrator."    
        }
        catch {
            throw $_
        }

    } else {
        try {
            $newKey = New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force -ErrorAction Stop
        }
        catch [System.Security.SecurityException] {
            Write-Output "Error: Security exception.  You need to run this script as administrator."    
        }
        catch {
            throw $_
        }
    }    

} # function Enable-DeveloperMode

function Get-WindowsVersion()
{
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $value = (Get-ItemProperty -Path $key -Name ReleaseId -ErrorAction SilentlyContinue).ReleaseId

    $version = [System.Environment]::OSVersion.Version
    if(($version -is [system.version]) -and ($value)) {
        $props = @{
            Major = $version.Major
            Build = $version.Build
            Release = $value
        }
        [pscustomobject]$props
    }

} # function Get-WindowsVersion

#endregion end functions

# Windows version checks
$version = Get-WindowsVersion
Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : Windows Major Version: $($version.Major), ReleaseId: $($version.Release)"
if($version -is [pscustomobject]) {
    if($version.Major -ne 10) {
        Write-Output "Error: This script is degined to only run on Windows 10."    
        exit 1
    } elseif(($version.Release -ne '1607') -and ($version.Release -ne '1703')) {
        # anniversary = 1607
        # creators = 1703
        Write-Output "Error: Unsupported release of Windows 10 - $($version.Release)."    
        exit 1        
    } elseif(($version.Release -as [int]) -ge 1709) {
        # creators fall = 1709
        Write-Output "Error: Use Windows Store to enable WSL functionality."    
        exit 1
    }
} else {
    Write-Output "Error: Failed to retrieve Windows version details."
    exit 1
}

# self-elevate
if($RunAs) {
    Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : -RunAs specified"
    if(-not (Test-RunAs)) {
        
        Enable-RunAs
    }
} else {
    Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : -RunAs not specified"
}

# Developer mode
if(Get-DeveloperMode) {
    Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : Developer mode already enabled"
} else {
    if(-not($CheckMode)) {
        if($Force) {
            Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : -Force switch specified, calling Enable-DeveloperMode"
            $devMode = Enable-DeveloperMode    
        } else {
            $readDevMode = Read-Host -Prompt "Enable Developer Mode? [y/n]"
            if($readDevMode -eq 'y') {
                Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : Selected to enable, calling Enable-DeveloperMode"
                $devMode = Enable-DeveloperMode    
            }
        }
    } else {
        Write-Output "CheckMode: Developer mode not currently enabled"    
    }
}


# WSL feature
if(Test-WSLInstalled) {
    Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : Windows Subsystem for Linux feature already enabled"
} else {
    if(-not($CheckMode)) {
        if($Force) {
            Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : -Force switch specified, calling Enable-WSLFeature"
            $enable = Enable-WSLFeature
        } else {
            $readEnable = Read-Host -Prompt "Enable Windows Subsystem for Linux feature? [y/n]"
            if($readEnable -eq 'y') {
                Write-Verbose -Message "$(Get-Date -Format HH:mm:ss) : $($($MyInvocation.Mycommand.Name).PadRight(32)) : Selected to enable, calling Enable-WSLFeature"
                $enable = Enable-WSLFeature    
            }
        }
    } 
    else {
        Write-Output "CheckMode: Windows Subsystem for Linux feature not currently enabled"
    }
}



Read-Host -Prompt "Press enter to continue"