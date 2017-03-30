#####################################
# File Name: Shutdown.ps1 v1.6
# Author: The Lads
# Date Created: January 26 2017
# Purpose: To finalize the automation process by releasing and locking any IPs or files
#####################################
$logfile = "c:\Temp\PSDeployment.log"
Function LogWrite
{
   Param ([string]$logstring)

   Add-content $Logfile -value $logstring
}

function Test-RegistryValue { 
    param ( 
        [parameter(Mandatory=$true)] 
        [ValidateNotNullOrEmpty()]$Path, 
        [parameter(Mandatory=$true)] 
        [ValidateNotNullOrEmpty()]$Value 
    ) 
    try { 
Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null 
        return $true 
    } catch { 
        return $false 
    } 
} 
########## REMOVE MICROSOFT APPS ##########
Get-AppxPackage -AllUsers | where-object {$_.name -notlike '*Microsoft.WindowsStore*'} | where-object {$_.name -notlike '*Microsoft.WindowsCalculator*'} | Remove-AppxPackage

########## LOCK THE BITLOCKER ENCRYPTION MANAGEMENT ##########
if (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DisallowCPL") {
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name DisallowCPL -PropertyType DWord -Value 1 | Out-Null
    New-item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DisallowCPL" | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DisallowCPL" -Name Bitlocker -PropertyType String -Value Microsoft.BitlockerDriveEncryption | Out-Null
}

########## DISABLE IPv6 ##########
if (Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Value 'DisabledComponents')
    {
    $log = "IPv6 Previously Disabled"
    Write-Host $log
    LogWrite $log
} else {
    New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' `
        -Name  'DisabledComponents' -Value '0xffffffff' -PropertyType 'DWord'
    $log = "IPv6 Disabled"
    Write-Host $log
    LogWrite $log
}

########## RELEASE IP & SET EXECUTION POLICY ##########
$AVActive = Get-Process NTRTScan -ErrorAction SilentlyContinue

if($AVActive -eq $null)
{
    Write-Host "Antivirus is not running!"
    Write-host "Install it and re-run this script"
    pause
    exit    
}
else
{
    Write-Host "Antivirus is running!"
        
}
ipconfig /release
Set-ExecutionPolicy -ExecutionPolicy Restricted -Force
#restart-computer
Stop-Computer