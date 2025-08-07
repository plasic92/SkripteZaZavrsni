
$customFolderCreate = "E:\VlastitoRiješenje\NovLogoovi\bruteforce\custom\FolderCreate.csv"
$customFolderDelete  = "E:\VlastitoRiješenje\NovLogoovi\bruteforce\custom\logDelete.csv"
$customFolderSecurity = "E:\VlastitoRiješenje\NovLogoovi\bruteforce\custom\logSecurityChange.csv"

$dcLogs = "E:\VlastitoRiješenje\NovLogoovi\bruteforce\factual\NewADLog.csv"

$FolderLogPath = "E:\VlastitoRiješenje\NovLogoovi\bruteforce\factual\FolderLog.csv"
$FolderPermissionsPath = "E:\VlastitoRiješenje\NovLogoovi\bruteforce\factual\FolderPermissionLog.csv"

$factualCSVOutput = "E:\VlastitoRiješenje\NovLogoovi\bruteforce\rezultat\FactuaBruteForcefolder.csv"
$CustomCsvOutput = "E:\VlastitoRiješenje\NovLogoovi\bruteforce\rezultat\CustomBruteForceFolder.csv"


function ParseFactualFolderLogs {
    param(
        $FolderLog = $Global:FolderLogPath,
        $FolderPermissions = $global:FolderPermissionsPath
    )
    $propPermissions = @(
    'FullPath','FileSystemRights','IdentityReference',@{n='PermissionChange'; e={'True'}}
    @{n='Created';e={'False'}},@{n='Deleted';e={'False'}},
    @{n='Removed'; e={'False'}},@{n='Renamed';e={'False'}}
    'NewFolderPath','OldFolderPath'
    )

    $propFolder = @(
    @{n='FullPath';e={$_.folderpath}},'FileSystemRights','IdentityReference',@{n='PermissionChange'; e={'False'}}
    'Created',@{n='Deleted';e={$_.delited}},
    @{n='Removed'; e={'False'}},'Renamed','NewFolderPath'
    @{n='OldFolderPath';e={
        if($_.Renamed -eq 'True'){
            $_.folderpath
        }
    }}
    
    )
    $FSfolder = Import-Csv -Path $FolderLog -Delimiter *|select $propFolder
    $FSpermissions = Import-Csv -Path $FolderPermissions -Delimiter *|select $propPermissions
    $logs = $FSpermissions + $FSfolder|sort -Property FullPath
    return $logs
}

function Get-CustomTimeStats {
    param(
        [array]$rawCustomData
    )

    $metodTimeDiff = {
        $time1 = [datetime]$this.TimeCreated.split(" ")[-1]
        $time2  = [datetime]$this.TimeReceived.split(" ")[-1]
        return ($time2 - $time1).TotalSeconds
    }
    $rawCustomData|ForEach-Object {
        $_|Add-Member -MemberType ScriptProperty -Name "TimeDiff" -Value $metodTimeDiff
    }

    $stats = $rawCustomData|Measure-Object -Property TimeDiff -AllStats
    return $stats
}

function Get-GroupSIDNameHashTable {
    param ($ADlogPATH)
    $hashGrupe = @{}
    $data = Import-Csv -Delimiter * -Path $ADlogPATH
    $grupe = $data|where {$_.created -eq 'True' -and $_.ADObjectType -eq 'Group'}
    $grupe.ForEach({$hashGrupe.Add($_.SID,"DOMENAZAPIS\$($_.samaccountname)")})
    return $hashGrupe
}

function Get-parsedCustomLogs {
    param(
        $dataCreate,
        $dataDelete,
        $dataSecurityChange
    )
$dsc = $dataSecurityChange|ForEach-Object {
    $FullPath = $_.ObjectName
    $object = ($_.NewSd|ConvertFrom-SddlString).RawDescriptor.DiscretionaryAcl
    ForEach($o in $object){
        if($hashBuilitnUsers.ContainsKey($o.SecurityIdentifier.value)){
            $id = $hashBuilitnUsers[$o.SecurityIdentifier.value]
        }else{
            $id = $hashGrupe[$o.SecurityIdentifier.value]
        }
        [pscustomobject]@{
            FullPath = $FullPath
            FileSystemRights = [System.Security.AccessControl.FileSystemRights]$o.AccessMask
            IdentityReference = $id
        }
    }
}

$dd = $dataDelete|ForEach-Object {
  
    [pscustomobject]@{
        FullPath = $_.ObjectName
    }

}

$dc = $dataCreate|select -Property FolderPath |sort -Property FolderPath -Unique
$dc = $dc|ForEach-Object {
  
    [pscustomobject]@{
        FullPath = $_.FolderPath
    }

}

    $propPermissions = @(
        'FullPath','FileSystemRights','IdentityReference',
        @{n='PermissionChange';e={'True'}},@{n='Created';e={'False'}},@{n='Deleted';e={'False'}},
        @{n='Removed';e={'False'}},
        @{n='Renamed';e={'False'}},
        @{n='NewFolderPath';e={'NoInfo'}},
        @{n='OldFolderPath';e={'NoInfo'}}
    )
    $propCreated = @(
        'FullPath','FileSystemRights','IdentityReference',
        @{n='PermissionChange';e={'False'}},@{n='Created';e={'True'}},@{n='Deleted';e={'False'}},
        @{n='Removed';e={'False'}},
        @{n='Renamed';e={'False'}},
        @{n='NewFolderPath';e={'NoInfo'}},
        @{n='OldFolderPath';e={'NoInfo'}}
        
    )

    $propDeleted = @(
        'FullPath','FileSystemRights','IdentityReference',
        @{n='PermissionChange';e={'False'}},@{n='Created';e={'False'}},@{n='Deleted';e={'True'}},
        @{n='Removed';e={'False'}},
        @{n='Renamed';e={'False'}},
        @{n='NewFolderPath';e={'NoInfo'}},
        @{n='OldFolderPath';e={'NoInfo'}}
        
    )

    $dsc = $dsc|select $propPermissions
    $dd = $dd|select $propDeleted
    $dc = $dc|select $propCreated

    return ($dsc + $dd + $dc)|sort -Property FullPath
}


$hashGrupe =  Get-GroupSIDNameHashTable -ADlogPATH $dcLogs
$hashBuilitnUsers = @{
    "S-1-5-32-544"="BUILTIN\Administrators"
    "S-1-5-32-545"="BUILTIN\Users"
    "S-1-3-0"="CREATOR OWNER"
    "S-1-5-18"="NT AUTHORITY\SYSTEM"
}

$dataCreate = Import-Csv -Delimiter * -Path $customFolderCreate
$dataDelete = Import-Csv -Delimiter * -Path $customFolderDelete
$dataSecurityChange = Import-Csv -Delimiter * -Path $customFolderSecurity




$stats = Get-CustomTimeStats -rawCustomData ($dataCreate + $dataDelete +$dataSecurityChange )




$customLogs = Get-parsedCustomLogs -datacreate $dataCreate -datadelete $dataDelete -dataSecurityChang $dataSecurityChange

$factualLogs = ParseFactualFolderLogs


$customLogs|ConvertTo-Csv -Delimiter * -QuoteFields s|Out-File -Path $CustomCsvOutput
$factualLogs|ConvertTo-Csv -Delimiter * -QuoteFields s|Out-File -Path $factualCSVOutput

