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
    $FactualDataALL = $FactualDataALL | Select-Object $prop|Sort-Object -Property TargetUserName

    

    return $FactualDataALL
}
