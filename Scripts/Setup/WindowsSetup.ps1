#####################################
# File Name: WindowsSetup.ps1 v2_2
# Author: Nigel Hughes, Thomas Machin
# Date Created: April 16 2017
# Purpose: To automate several parts of the configuration process after having logged on for the first time
#####################################
$scriptVer = "v2.2.1 April 16 2017";

$CSVFileName = ' ';
$mapTarget = ' ';
$mapUser = ' ';
$mapPW = ' ';
$CSVPath = "Z:\Excel Files\$CSVFileName";

$timeStamp = Get-Date -format yyyy-MM-d-hhmmss
$transcriptLogfile = "setuplog-$timestamp.txt";
Start-Transcript -Path "C:\temp\deployment\logs\$transcriptLogfile" -NoClobber -IncludeInvocationHeader

#Create a Log File for Error Reporting
$logfile = "c:\Temp\PSDeployment.log"
Function LogWrite
{
   Param ([string]$logstring)

   Add-content $Logfile -value $logstring
}

function Create-User ($userName, $userPW, $userGroup) {  
    New-LocalUser -Name $username -Password $userPW -PasswordNeverExpires
    if (Get-LocalGroup $userGroup){
        Add-LocalGroupMember -Group $userGroup -Member $userName
    }  
}

function Test-UserCreation ($username,$userGroup) {
    $pw = ConvertTo-SecureString "Test" -AsPlainText -Force
    Create-User $username $pw $userGroup;

    if (Get-LocalUser $username){
        write-host "$username Created Succesfully";
    } else {
        Write-Host "$username does not exist.";
    }
    if (Get-LocalGroupMember -group $userGroup -member $username){
        write-host "$username added to $userGroup Successfully";
    } else {
        write-Host "$Username is not a member of $userGroup";
    }
    Write-Host "Removing test user $userName";
    Remove-LocalUser $username
    if (Get-LocalUser $username){
        write-host "$username was not removed successfully";
    } else {
        Write-Host "$username was removed.";
    }

}

function Access-Excel {
    ########## CREATE LOCK FILE ##########
    $lock = test-path "Z:\Excel Files\excellock.lock"

    while ($lock -eq $true) {
        write-host "Lock file present. Please Wait..."
        Start-Sleep -s 5
        $lock = test-path "Z:\Excel Files\excellock.lock"
    }
    new-item -path "Z:\Excel Files\excellock.lock" -type "file";
    Write-Host "File successfully locked";
            
    $objCSV = Import-CSV $CSVPath;
    $rowMax = ($objCSV.Rows).count;    

    ########## PARSE FOR ID ###########    
    $log = "Parsing through CSV Sheet"

    LogWrite $log
    Write-Host $log
    $SN = gwmi win32_bios | Select –ExpandProperty SerialNumber;
    $CSVIndex = 0;
    #checks each row in CSV file. If row contains a serial that matches, then the script grabs the detail from that row. Or, if the 
    #script encounters an empty serial field, it will grab the information from that row. 
    #WARNING - If the CSV contains duplicate serials, the values from the first occurance will be used
    #WARNING - If the CSV contains an empty cell in the Serial column, it will use that row and not search further for matches.
    foreach ($row in $objCSV){       
        if ($SN -eq $row.Serial) {
            $PCName = $row.PCName;
            $UserName = $row.UserName;
            $UserPW = ConvertTo-SecureString $row.UserPW -AsPlainText -Force;
            $EncryptPW = ConvertTo-SecureString $row.EncryptPW -AsPlainText -Force;$row.EncryptPW;            
            $log = "Serial Match:$SN has been found in the excel file, name will remain $PCName";
            LogWrite $log ;
            Write-Host $log;
            $CSVRow = $CSVIndex;
            break
        } elseif ($row.serial -eq ""){            
            $PCName = $row.PCName;
            $UserName = $row.UserName;
            $UserPW = ConvertTo-SecureString $row.UserPW -AsPlainText -Force;
            $EncryptPW = ConvertTo-SecureString $row.EncryptPW -AsPlainText -Force;
            $CSVRow = $CSVIndex;            
            $row.Serial = $SN;
            write-host "Empty Serial Found on Row $CSVRow";
            #write-host $CSVRow;
            $log = "New Computer Name selected: " + $PCName;
            LogWrite $log;
            Write-Host $log;
            break
        }
        $CSVIndex++;       
        
    }

    
    
    ##Create User###
    $group = 'Administrators'
    Create-User ($userName, $userPW, $group);
    
    
    #Enable bitlocker using the encryption password from the CSV
    Enable-BitLocker -MountPoint C: -Pin $EncryptPW -TpmAndPinProtector -EncryptionMethod XtsAes256 -SkipHardwareTest -UsedSpaceOnly
    Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
    $BitLocker = Get-BitLockerVolume -MountPoint C:
    foreach ($a in $BitLocker.KeyProtector){
        if ($a.KeyProtectorType -eq "RecoveryPassword"){
            $RecoveryPassword = $a.RecoveryPassword
            $KeyProtectorId = $a.KeyProtectorId
        }
    }

    ########## WRITE VALUES TO EXCEL ############ 
    #Modify CSV with new values
    foreach ($row in $objCSV){     
        if ($row.serial -eq $SN){
            $row.BitlockerID = $KeyProtectorId;
            $row.BitlockerKey = $RecoveryPassword;
        }
    }
    $objCSV | Export-csv "$CSVPath";
    $objCSV | Export-csv "Z:\Excel Files\Backup\csvBackup$(get-date -f MM_dd_yyyy_HHmmss).csv";

    mkdir C:/Temp/BitLocker
    $RecoveryPassword>'C:/Temp/BitLocker/RecoveryPassword.txt'
    $KeyProtectorId>'C:/Temp/BitLocker/KeyProtectorID.txt'
    $BitRecovery = 'Z:\Excel Files\BitLockerKeys\'+$KeyProtectorId+'RecoveryPassword.txt'
    $RecoveryPassword>$BitRecovery
    
    Start-Sleep -s 3
    remove-item -path "Z:\Excel Files\excellock.lock"
    $log = "Excel File " + $CSVPath + " Closed and Saved"
    LogWrite $log
    write-host $log;
    Start-Sleep -s 5;
    #write-host "ED: " + $ED;
    return $PCName;
}

####################    START SCRIPT    ##################################################
#copy new default taskbar into place.
Copy-Item "C:\temp\deployment\prelogon\Taskbar\*" "$windowsDrive\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Force;   

#remove cached tile data, allowing custom start menu to work.
Remove-Item "C:\Users\Default\AppData\Local\TileDataLayer" -recurse;

########## INITIATE UPDATE PROCESS ##########

Write-Host ="Windows Setup Script :  $scriptVer";

Write-Host "Beginning update process... `n`n";

########## SET FILE EXTENSIONS TO VISIBLE ##########
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f
$log = "File extensions set to visible"
Write-Host $log
LogWrite $log

########## MAP TO SHARED EXCEL ##########
$gateway = (Get-wmiObject Win32_networkAdapterConfiguration | ?{$_.IPEnabled}).DefaultIPGateway
while (!($gateway)) {
        Write-Host "Ethernet is Not Plugged in, Please plug in the ethernet to continue"
        Read-Host -Prompt "Press Enter to continue"
        $gateway = (Get-wmiObject Win32_networkAdapterConfiguration | ?{$_.IPEnabled}).DefaultIPGateway
}
try {
    $PWord = ConvertTo-SecureString -String $mapPW -AsPlainText -Force;
    $mapCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $mapUser, $PWord;  
    New-PSDrive -Name "Z" -PSProvider FileSystem -Root "$mapTarget" -Persist -Credential $mapCredential;
} Catch { 
    write-host "Network Previously Mapped"
}
LogWrite "Network Drive Mapped"
Write-Host "Network Drive Mapped"

########## REMOVE TEMPORARY USERS ##########
try {
    $Computer = $env:COMPUTERNAME
        $ADSIComp = [adsi]"WinNT://$Computer"
    $ADSIComp.Delete('User','removeMe')
} catch {
    write-host "User Previously Deleted"
}
LogWrite "removeMe User Successfully Removed"
Write-Host "removeMe User Successfully Removed"

try {
    $Computer = $env:COMPUTERNAME
        $ADSIComp = [adsi]"WinNT://$Computer"
    $ADSIComp.Delete('User','defaultuser0')
} catch {
    write-host "User Previously Deleted"
}
LogWrite "defaultuser0 User Successfully Removed"
Write-Host "defaultuser0 User Successfully Removed"

########## ACCESS SYSTEM INFORMATION ##########
$SN = gwmi win32_bios | Select –ExpandProperty SerialNumber;

#$SN = $SN -replace ".*=" -replace "}.*"
$log = "Computer Serial Number: " + $SN
LogWrite $log
Write-Host $log
$NewID = Access-Excel
$NewID -split " "
$NewID = $NewID[$NewID.Length-1]
write-host "NewID: "$NewID

######### Sync Time + Activate Windows #####
W32tm /resync /force
slmgr /ato

########## RENAME PC ############
(Get-WmiObject Win32_ComputerSystem).Rename($NewID)
$log = "Computer Renamed to " + $NewID
LogWrite $log
write-host $log

########## REMOVE STARTUP.CMD ############
$startupPath = test-path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\startup.cmd'
if ($startupPath) {
    Remove-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\startup.cmd'
} else {
    Write-Host "Startup.cmd not found in the startup folder"
}
##Disable SmartScreen
Write-Host "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"

##Remove Dymo Label Shortcut if it exists
Remove-Item -Path "C:\users\public\desktop\Dymo Label v.8.lnk";

##SETUP IE
CMD /c REG add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_EUPP_GLOBAL_FORCE_DISABLE" /v "iexplore.exe" /t REG_DWORD /d 1 /f'

#run IE11 config, sets homepages and search
Invoke-Expression 'C:\temp\Deployment\Prelogon\IE11StartPages.msi /n /passive /norestart';

#Install AV if it is not already installed.
$AVCheck = test-path "C:\Program Files (x86)\Trend Micro\OfficeScan Client\PccNT.exe"
if ($AVCheck -ne $true) {
   Write-host "Av not found";
   Invoke-Expression 'msiexec /i C:\temp\Deployment\Prelogon\agent_cloud_x64.msi /qb /norestart';
}

########## LOCK THE BITLOCKER ENCRYPTION MANAGEMENT ##########
if (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DisallowCPL") {
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name DisallowCPL -PropertyType DWord -Value 1 | Out-Null
    New-item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DisallowCPL" | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DisallowCPL" -Name Bitlocker -PropertyType String -Value Microsoft.BitlockerDriveEncryption | Out-Null
}

<########### RESET EXECUTION POLICY ############
Set-ExecutionPolicy -ExecutionPolicy Restricted -Force
LogWrite "execution policy reset"
#>

Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
Write-host "`n`n********************************************"
Write-host "`n********************************************"
write-host -foreground "green" -background 'Black' "`nNew User ID = $NewID";
Write-host "`n********************************************"
Write-host "`n`n********************************************"
Read-Host -Prompt "Configuration Complete!`n "
pause
LogWrite "Restarting Computer..."
Stop-Transcript;
Restart-Computer
exit