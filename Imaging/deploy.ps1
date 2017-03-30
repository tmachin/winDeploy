<#
Windows Imaging Script
-By Thomas Machin
--Run from Windows PE 5+ with powershell components installed.
--Finds .wim files from subdirectoryies, presents them to user as a choice.
--Chosen image is checked to see what windows version it is, and then mbr or gpt partitions are created and image is applied.
--Scripts are then copied into place to enable an unattended setup of windows, unless parameters indicate otherwise.

#>
#command line parameters to skip certain setup stages. set what stages get copied by the deploy script
Param(
  [string]$useUnattend = $true, #copies the unattend.xml file from the scriptfolder\unattend\ folder to the PC being imaged
  [string]$usePreLogon = $true,
  [string]$useSetup = $true,
  [string]$usePerUser = $true,
  [string]$restartOnComplete = $true,
  [string]$file = ""
)

$scriptVer = "Version 1.7.3 - Feb 23, 2017"

write-host "Windows Imaging Script " $scriptVer -foreground "green" -background 'Black';

$scriptPath = $PSScriptRoot;
$scriptDrive = (get-location).Drive.Name + ":";
$windowsDrive = "W:";
$timeStamp = Get-Date -format yyyy-MM-d-hhmmss
$logfile = "deploylog-$timestamp.txt";

Write-Host "Script Drive: $scriptDrive"; 
Start-Transcript -Path "$scriptDrive\logs\$logfile" -NoClobber -IncludeInvocationHeader

#Set Powercfg to high power mode for better performance
Invoke-Expression "powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"

#Set variables to store where the script is run from
$ImgPath = $scriptPath;

write-verbose "Script Path: $scriptPath";
$filepath = $file;
if ($filePath -eq [string]::empty){

    $imgDir = get-childitem $ImgPath -recurse;
    $imgList = $imgDir | where {$_.Extension -eq ".wim"};

    #list all .wim files on the folder and subfolder of the path where the script was run.
    #append a number to the image information, so that it can be selected.
    $i = 0;
    foreach ($imgFile in $imgList)
    {    
        $filePath = "$($imgFile.Directory)\$($imgFile)";
        $details = Get-WindowsImage -ImagePath:$filePath -index:1;
        Write-Host "$i -($filePath) Windows V. - $($details.version) - $($details.editionId)`n";   
        $i++;
    }

    #Prompt user to select number of image from array
    $imgChoice = read-host -Prompt "Enter Number Of Image to Install";

    if ($imgChoice -eq [string]::empty){
        throw 'No Input Entered';
    } else {
        Try{
            #throws error if array item referenced does not exist   
            if ($imgList[$imgChoice] -eq $null) { 
                write-host 'Selection Not in Array':
                write-host 'Invalid Image Choice. Please Rerun script and select again.';    
                throw
            } else {
                $filePath = "$($imgList[$imgChoice].Directory)\$($imgList[$imgChoice])";   
                write-verbose $filePath;
            }
        } catch {
        write-warning "Invalid image choice - Rerun script and select again.";
        exit
        }
    }
} else {
    Write-Verbose "Using filepath from command line parameter";
}

#Get Windows version of specified wim file
$details = Get-WindowsImage -ImagePath:$filePath -index:1;
[int]$imgVersion = $details.version.Substring(0,2);

write-verbose "Image file : $filePath"
write-verbose "Windows image Version: $imgVersion";

write-host "                     Windows Deployment Script                              " -foreground "yello" -background 'Black';
write-host '                                                                            ' -foreground "red" -background 'Black';
write-host '   Brought to you by:                                                       ' -foreground "red" -background 'Black';
write-host '$$$$$$$$\ $$\   $$\ $$$$$$$$\       $$\        $$$$$$\  $$$$$$$\   $$$$$$\  ' -foreground "yellow" -background 'Black'; 
write-host '\__$$  __|$$ |  $$ |$$  _____|      $$ |      $$  __$$\ $$  __$$\ $$  __$$\ ' -foreground "yellow" -background 'Black';
write-host '   $$ |   $$ |  $$ |$$ |            $$ |      $$ /  $$ |$$ |  $$ |$$ /  \__|' -foreground "yellow" -background 'Black';
write-host '   $$ |   $$$$$$$$ |$$$$$\          $$ |      $$$$$$$$ |$$ |  $$ |\$$$$$$\  ' -foreground "yellow" -background 'Black';
write-host '   $$ |   $$  __$$ |$$  __|         $$ |      $$  __$$ |$$ |  $$ | \____$$\ ' -foreground "yellow" -background 'Black';
write-host '   $$ |   $$ |  $$ |$$ |            $$ |      $$ |  $$ |$$ |  $$ |$$\   $$ |' -foreground "yellow" -background 'Black';
write-host '   $$ |   $$ |  $$ |$$$$$$$$\       $$$$$$$$\ $$ |  $$ |$$$$$$$  |\$$$$$$  |' -foreground "yellow" -background 'Black';
write-host '   \__|   \__|  \__|\________|      \________|\__|  \__|\_______/  \______/ ' -foreground "yellow" -background 'Black';
write-host '                                                                            ' -foreground "yellow" -background 'Black';

#Run diskpart to format drive and set partitions for windows 10 or windows 7
if ($imgVersion -ge 10){
    write-verbose 'Windows 10 Image - using UEFI boot settings';
    $diskpartFile = "$scriptDrive\imaging\diskpart_win10.txt";
    $windowsDrive = 'W:';    
} elseif ($imgVersion -lt 10){
    write-verbose 'Image Windows Version below Windows 10 - using mbr boot settings';
    $diskpartFile = "$scriptDrive\imaging\diskpart.txt";
    $windowsDrive = 'C:';
}

diskpart /s $diskpartFile;

write-verbose "--------------------";
write-verbose "Diskpart complete ;)";
write-verbose "--------------------";

#apply the image file with dism.exe

if ($imgVersion -ge 10.0){

    dism /apply-image /imagefile:$filePath /index:1 /ApplyDir:W:\

    #Copy Boot files to system partition
    #w:\Windows\System32\bcdboot W:\Windows /s S:
    $cmd = "$windowsDrive\Windows\System32\bcdboot W:\Windows /s S:"
    Invoke-Expression $cmd
    
    #Move recovery files to the recovery partition, then register them.
    New-Item R:\Recovery\WindowsRE -type directory    
    #copy w:\Windows\System32\Recovery\winre.wim R:\Recovery\WindowsRE\winre.wim
    Copy-Item -Path w:\Windows\System32\Recovery\winre.wim -Destination R:\Recovery\WindowsRE\winre.wim
    
    #w:\Windows\System32\reagentc /setreimage /path R:\Recovery\WindowsRE /target w:\Windows
    $cmd = "$windowsDrive\Windows\System32\reagentc /setreimage /path R:\Recovery\WindowsRE /target $windowsDrive\Windows"
    Invoke-Expression $cmd
    #w:\Windows\System32\Reagentc /Info /Target w:\Windows
    $cmd = "$windowsDrive\Windows\System32\Reagentc /Info /Target $windowsDrive\Windows"
    Invoke-Expression $cmd;

    write-host Recovery Partition and Boot partition set
    write-verbose '********************'
    write-verbose 'Recovery Partition Setup Complete \(0-0)/'
    write-verbose '********************'
    
} elseif ($imgVersion -lt 10.0){
    #set boot settings
    dism /apply-image /imagefile:$filePath /index:1 /ApplyDir:C:\
    bcdedit /set {default} device partition=c:
    bcdedit /set {default} osdevice partition=c:
    bcdedit /set {bootmgr} device partition=c:    
}

write-verbose '********************'
write-verbose 'Image Complete! :)'
write-verbose '********************' 

if ($useUnattend){
    #Copies unattend.xml into place. (Image must have been sysprep /generalized with an .xml file for all unattend settings to be applied.      
    if ($imgVersion -ge 10){        
        Copy-Item $scriptDrive\unattend\unattend10.xml "$windowsDrive\Windows\Panther\unattend.xml" -force;
        write-verbose 'Win 10 Unattend File Deployed.';
    } elseif ($imgVersion -lt 10){        
        Copy-Item $scriptDrive\unattend\unattend7.xml "$windowsDrive\Windows\Panther\unattend.xml" -force;
        write-verbose 'Win 7 Unattend File Deployed.';        
    }    
}
New-Item "$windowsDrive\temp\Deployment" -type directory;
if ($usePreLogon){
    #copies scripts and files that are used BEFORE the first user logs in
    New-Item "$windowsDrive\temp\Deployment\Prelogon" -type directory;   
    Copy-Item "$scriptDrive\Scripts\PreLogOn\*" "$windowsDrive\temp\Deployment\Prelogon" -Recurse;
    New-Item "$windowsDrive\Windows\Setup\Scripts" -type directory;
    Copy-Item "$windowsDrive\temp\Deployment\Prelogon\SetupComplete.cmd" "$windowsDrive\Windows\Setup\Scripts";
    write-verbose 'Pre-Logon Files Deployed.'; 

    #copy new default taskbar into place.
    Copy-Item "$scriptDrive\Prelogon\Taskbar\*" "$windowsDrive\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Force;    

    #remove cached tile data, allowing custom start menu to work.
    Remove-Item "$windowsDrive\Users\Default\AppData\Local\TileDataLayer" -recurse;   
}

if ($useSetup){
    #Copy files that will be run on first log in
    New-Item "$windowsDrive\temp\Deployment\Setup" -type directory;   
    Copy-Item "$scriptDrive\Scripts\Setup\*" "$windowsDrive\temp\Deployment\Setup" -Recurse;
    Copy-Item "$windowsDrive\temp\Deployment\Setup\startup.cmd" "$windowsDrive\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";
    write-verbose 'User Setup Files Deployed.';
}

if ($usePerUser){
    #Copy files that will be run every time a new user logs into this machine, they will remove the language bar
    New-Item "$windowsDrive\temp\Deployment\NewUser" -type directory;
    Copy-Item "$scriptDrive\Scripts\NewUser\*" "$windowsDrive\temp\Deployment\NewUser" -Recurse;    
    New-Item "$windowsDrive\users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -type directory;
    Copy-Item "$windowsDrive\temp\Deployment\NewUser\newUserSetup.lnk" "$windowsDrive\users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";
    write-verbose 'Per User Settings Files Deployed.';
}

write-host 'Deploy Script Complete.';
Stop-Transcript;
New-Item "$windowsDrive\temp\deployment\logs\" -type directory;
Copy-Item $scriptDrive\logs\$logfile $windowsDrive\temp\deployment\logs\$logfile
write-verbose 'Logfile Copied to local machine';
if ($restartOnComplete){
    #pause for 10 seconds to allow results to be seen    
    write-host 'Restarting in 10 Seconds. Press Ctrl-C to cancel.' -foreground "green" -background 'Black';
    Start-Sleep -Seconds 10;
    restart-computer;
}
