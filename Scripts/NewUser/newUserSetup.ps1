#Hide Language Bar, and disable Language hot-key
#Author: Thomas Machin
$logfile = "c:\Temp\PSDeployment.log"
Function LogWrite
{
   Param ([string]$logstring)

   Add-content $Logfile -value $logstring
}
control /name Microsoft.DefaultPrograms /page pageDefaultProgram

Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name HotKey -Value 3
New-Item -Path 'HKCU:\Software\Microsoft\CTF\LangBar' -ItemType Key
New-ItemProperty -Path 'HKCU:\Software\Microsoft\CTF\LangBar' -Name Showstatus -PropertyType DWord -Value 3
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\CTF\LangBar' -Name Showstatus -Value 3
LogWrite "Language Bar Removed and Hot Key Disabled"
#Set the Short Date format to have year at the beginning
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value yyyy-MM-dd

#set background color
#remove wallpaper
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value ""
#set color to 0 99 177 (blue)
Set-ItemProperty -Path "HKCU:\Control Panel\Colors" -Name Background -Value "0 99 177"

Remove-Item -Path "C:\users\public\desktop\Dymo Label v.8.lnk";
  
#Write-Host "***Disabling Suggested Apps, Feedback, Lockscreen Spotlight***"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\" /t REG_DWORD /v SystemPaneSuggestionsEnabled /d 0 /f
reg add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\SoftLandingEnabled" /t REG_DWORD /v SoftLandingEnabled /d 0 /f
reg add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /t REG_DWORD /v RotatingLockScreenEnable /d 0 /f

#Let apps use my advertising ID for experiences across apps (turning this off will reset you ID)
if (Test-Path -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo\Enabled') {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -PropertyType DWord -Value 0 | Out-Null
} elseif (Test-Path -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'){
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -PropertyType DWord -Value 0 | Out-Null
} else {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -PropertyType DWord -Value 0 | Out-Null        
} 
if (Test-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Value 'EnableBalloonTips') 
    {write-host "Notification Balloons already disabled"
} else {
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name EnableBalloonTips -PropertyType DWord -Value 0 | Out-Null
}
#Let apps use my advertising ID for experiences across apps (turning this off will reset you ID)
New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -PropertyType DWord -Value 0 | Out-Null
#Let Websites Provide Locally Relevant Content
New-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -PropertyType DWord -Value 1 | Out-Null
#Location Services **Works
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name Value -Value "Deny" | Out-Null
#Camera            **Works
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name Value -Value "Deny" | Out-Null
#Microphone        **Works
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" -Name Value -Value "Deny" | Out-Null
#Notifications     **Works
if (Test-Path -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}') {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Name Value -Value "Deny" | Out-Null
} else {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}"
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Name Value -Value "Deny" | Out-Null
}
#Contacts
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Name Value -Value "Deny" | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Name Value -Value "Deny" | Out-Null
#Calendar          **Works
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Name Value -Value "Deny" | Out-Null
#Call History has no apps turned on by default
#Messaging
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Name Value -Value "Deny" | Out-Null
#Radios            **Test Again
if (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}") {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Name Value -Value "Deny" | Out-Null
} else {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}"
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Name Value -Value "Deny" | Out-Null
}
#Other Devices      **Works
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name Value -Value "Deny" | Out-Null

Get-AppxPackage -AllUsers | where-object {$_.name -notlike "*Microsoft.WindowsStore*"} | where-object {$_.name -notlike "*Microsoft.WindowsCalculator*"} | Remove-AppxPackage 

##Disable SmartScreen
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -ErrorAction Stop -Value "Off" -Force

########## RESET EXECUTION POLICY ############
Set-ExecutionPolicy -ExecutionPolicy Restricted -Force
LogWrite "execution policy reset"
