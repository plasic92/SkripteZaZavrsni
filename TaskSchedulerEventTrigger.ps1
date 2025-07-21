# taken from: https://github.com/phbits/

# NOTE - ExecutionPolicy set to Unrestricted should only be used for testing.



#change .\TriggerOnFolderCreate.ps1,'C:\Users\Administrator.DOMENAZAPIS\Desktop\skripte'

$Action = New-ScheduledTaskAction -Execute 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe' `
        -Argument '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -File .\TriggerOnFolderCreate.ps1 -RecordID $(eventRecordID) -ExecutionPolicy Unrestricted' `
        -WorkingDirectory 'C:\Users\Administrator.DOMENAZAPIS\Desktop\skripte'
 
$Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount
 
$Settings = New-ScheduledTaskSettingsSet -DisallowDemandStart -Compatibility Win8 -Hidden -WakeToRun `
                                         -RunOnlyIfNetworkAvailable -AllowStartIfOnBatteries
 
$Settings.RunOnlyIfIdle = $FALSE
$Settings.ExecutionTimeLimit = 'PT1H'
$Settings.StartWhenAvailable = $TRUE
$Settings.StopIfGoingOnBatteries = $FALSE
$Settings.DisallowStartOnRemoteAppSession = $FALSE
$Settings.DisallowStartIfOnBatteries = $FALSE
$Settings.Priority = 3
 
# Create Trigger via Security Event ID 1102
$cimTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger `
                                -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger

$qr= @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=11)] and EventData[Data[@Name='RuleName']='ShareCreated']]
    </Select>
  </Query>
</QueryList>
"@

$Trigger = New-CimInstance -CimClass $cimTriggerClass -ClientOnly
$Trigger.Subscription = $qr

$Trigger.ExecutionTimeLimit = 'PT1H'
$Trigger.Enabled = $TRUE
 
# Set ValueQueries so the RecordID can be passed to the script
$Trigger.ValueQueries = [CimInstance[]] $(Get-CimClass -ClassName MSFT_TaskNamedValue -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskNamedValue)
 
#pass even
$Trigger.ValueQueries[0].Name = 'eventRecordID'
$Trigger.ValueQueries[0].Value = 'Event/System/EventRecordID'
 
Register-ScheduledTask -TaskName 'shellTriggerOnFolderCreate' `
                       -Description 'Run script on sysmon Event 11' `
                       -TaskPath '\' `
                       -Action $Action `
                       -Trigger $Trigger `
                       -Settings $Settings `
                       -Principal $Principal