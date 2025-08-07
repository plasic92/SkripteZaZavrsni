$factualDCLogsPath="E:\VlastitoRiješenje\aNoviLogovi\bruteforce\factualBruteForce\NewADLog.csv"

$items = Get-ChildItem -Path E:\VlastitoRiješenje\aNoviLogovi\bruteforce -File
$dataList = [System.Collections.ArrayList]::new()
$items|ForEach-Object {
    $d = import-csv -Delimiter * -Path $_.FullName
    [void]$dataList.Add($d)
}
$data = $dataList.ForEach({$_})
function Get-FactualLogs {
    param($factualDCLogsPath = $Global:factualDCLogsPath)

    $FactualDataALLRaw = Import-Csv -Delimiter * -Path $factualDCLogsPath

    $FactualDataGM = $FactualDataALLRaw|where {$_.Added -eq 'True' -or $_.Removed -eq 'True'}
    $FactualDataGroup = $FactualDataALLRaw|where {$_.ADObjectType -eq 'group'}
    $FactualDataUser = $FactualDataALLRaw|where {$_.Created -eq 'True' -or $_.delited -eq 'True' -or $_.Disabled -eq 'True' -and $_.ADObjectType -eq 'user'}

    $TargetUserName = @{n='TargetUserName';e={$_.inGroup}}
    $TargetSid = @{n='TargetSid';e={$_.inGroupSID}}
    $MemberName = @{n='MemberName';e={$_.DistinguishedName}}
    $MemberSid = @{n='MemberSid';e={$_.sid}}
    $Deleted = @{n='Deleted';e={$_.Delited}}
    $FactualDataGM = $FactualDataGM|select $TargetUserName,$TargetSid,$MemberName,$MemberSid,Created,$Deleted,Disabled,Added,Removed,ADObjectType,GroupScope

    $TargetUserName = @{n='TargetUserName';e={$_.SamAccountName}}
    $TargetSid = @{n='TargetSid';e={$_.SID}}
    $Deleted = @{n='Deleted';e={$_.Delited}}
    $FactualDataGroup = $FactualDataGroup|select $TargetUserName,$TargetSid,Created,$Deleted,Disabled,Added,Removed,ADObjectType,GroupScope

    $FactualDataUser = $FactualDataUser|select $TargetUserName,Created,$Deleted,Disabled,Added,Removed,ADObjectType

    $FactualDataALL = $FactualDataGM + $FactualDataGroup + $FactualDataUser

    $prop = @(
        'TargetUserName','TargetSid','MemberName'
        'MemberSid','Created','Deleted',
        'Disabled','Added','Removed'
        'ADObjectType','GroupScope'
    )
    $FactualDataALL = $FactualDataALL | Select-Object $prop|Sort-Object -Property $prop -Unique

    
    <#
    $FactualLogsAll = $FactualLogsAll|ForEach-Object {
        $buff = $_.ADObjectType
        $_.ADObjectType = $buff.ToLower()
        $_
   }
#>

    

    return $FactualDataALL
}
function Add-Properties {
    param($dataObject)
    $object = $dataObject|select TargetUserName,TargetSid,MemberName,MemberSid,Created,Deleted,Disabled,Added,Removed,ADObjectType,GroupScope
    $AddDifference = $ADOperations|where {$_.id -eq $dataObject.EventID}
    $object.Created = $AddDifference.Created
    $object.Deleted = $AddDifference.Deleted
    $object.Disabled = $AddDifference.Disabled
    $object.Added = $AddDifference.Added
    $object.Removed = $AddDifference.Removed
    $object.ADObjectType = $AddDifference.ADObjectType
    $object.GroupScope = $AddDifference.GroupScope
    return $object
}

$ADOperations = @"
"Operation","ID","Description","Created","Deleted","Disabled","Added","Removed","ADObjectType","GroupScope"
"GroupMemberOperation","4728","member was added to a security-enabled global group","False","False","False","True","False","User","Global"
"GroupMemberOperation","4732","member was added to a security-enabled local group","False","False","False","True","False","User","DomainLocal"
"GroupMemberOperation","4756","member was added to a security-enabled universal group","False","False","False","True","False","User","Universal"
"GroupMemberOperation","4729","member was removed from a security-enabled global group","False","False","False","False","True","User","Global"
"GroupMemberOperation","4733","member was removed from a security-enabled local group","False","False","False","False","True","User","DomainLocal"
"GroupMemberOperation","4757","member was removed from a security-enabled universal group","False","False","False","False","True","User","Universal"
"GroupOperation","4727","security-enabled global group was created","True","False","False","False","False","group","Global"
"GroupOperation","4730","security-enabled global group was deleted","False","True","False","False","False","group","Global"
"GroupOperation","4731","security-enabled local group was created","True","False","False","False","False","group","DomainLocal"
"GroupOperation","4734","security-enabled local group was deleted","False","True","False","False","False","group","DomainLocal"
"GroupOperation","4754","security-enabled universal group was created","True","False","False","False","False","group","Universal"
"GroupOperation","4758","security-enabled universal group was deleted","False","True","False","False","False","group","Universal"
"UserOperation","4720","user account was created","True","False","False","False","False","User",""
"UserOperation","4726","user account was deleted","False","True","False","False","False","User",""
"UserOperation","4725","user account was disabled","False","False","True","False","False","User",""
"@

$ADOperations = $ADOperations|ConvertFrom-Csv

$metodaTimeDiff = {
    $time1 = [datetime]$this.TimeCreated
    $time2 = [datetime]$this.TimeReceived
    return ($time2 - $time1).TotalSeconds
}

$data|ForEach-Object {
    $_|Add-Member -MemberType ScriptProperty -Name "DateTimeDiff" -Value $metodaTimeDiff -Force
}

$data|Measure-Object -Property DateTimeDiff -AllStats




$CustomLogs = $data|ForEach-Object {
    Add-Properties -dataObject $_
}





$CustomLogs = $CustomLogs|sort -Property TargetUserName

$FactualLogsAll = Get-FactualLogs
$FactualLogsAll = $FactualLogsAll|sort -Property TargetUserName

$FactualLogsAll.Count

$FactualLogsAll|ConvertTo-Csv -Delimiter * -QuoteFields s|Out-File -FilePath E:\VlastitoRiješenje\aNoviLogovi\bruteforce\rezultati\FactualBruteForceCustomADLogs.csv
$CustomLogs|ConvertTo-Csv -Delimiter * -QuoteFields s|Out-File -FilePath E:\VlastitoRiješenje\aNoviLogovi\bruteforce\rezultati\BruteForceCustomADLogs.csv





<#
$CustomLogs|select ADObjectType|sort -Property ADObjectType -CaseSensitive -Unique
$FactualLogsAll|select ADObjectType|sort -Property ADObjectType -CaseSensitive -Unique

$FactualLogsAll = $FactualLogsAll|ForEach-Object {
    $buff = $_.ADObjectType
    $_.ADObjectType = $buff.ToLower()
    $_
}
#>

