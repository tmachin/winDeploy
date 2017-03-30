$scriptDrive = (get-location).Drive.Name + ":";
$windowsDrive = "W:";
$timeStamp = Get-Date -format yyyy-MM-d-hhmmss
$logfile = "prelogonlog-$timestamp.txt";

Start-Transcript -Path "C:\temp\deployment\logs\$logfile" -NoClobber -IncludeInvocationHeader

#activate admin account and clear out extra users
Invoke-Expression 'net user administrator /active:yes';
Invoke-Expression 'net user removeMe /DELETE';
Invoke-Expression 'net user default0 /DELETE';

#import powerplan that doesn't let usb ports fall asleep. (Fixes bug on dell 3570 laptops)

Invoke-Expression 'powercfg -import "C:\temp\Deployment\Prelogon\PowerPlanBackup.pow" 69d8c0ae-b248-4d7f-8d01-a24722ab4a78';
Invoke-Expression 'powercfg -setactive 69d8c0ae-b248-4d7f-8d01-a24722ab4a78';

#Disable Smartscreen
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off";

#install Anti virus
Invoke-Expression 'msiexec /i C:\temp\Deployment\Prelogon\agent_cloud_x64.msi /quiet /norestart';

#run IE11 config, sets homepages and search
Invoke-Expression 'C:\temp\Deployment\Prelogon\IE11StartPages.msi /n /passive /norestart';

#copy new default taskbar/startmenu into place.
Copy-Item "C:\temp\Deployment\Prelogon\taskbar\" "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" -force;

#remove cached tile data, allowing custom start menu to work.
Remove-Item "C:\Users\Default\AppData\Local\TileDataLayer" -recurse -force;

Stop-transcript;