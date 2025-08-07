$WazuhLogsRaw = "E:\LogoviBruteForcing\WAZUH\normalniLogovi\fsNormal.csv"
$dcLogs = "E:\LogoviBruteForcing\WAZUH\bruteForsingUpdate\factualLogs\NewADLogOld.csv"

$FolderLogPath = "E:\LogoviBruteForcing\WAZUH\bruteForsingUpdate\factualLogs\FolderLog.csv"
$FolderPermissionsPath = "E:\LogoviBruteForcing\WAZUH\bruteForsingUpdate\factualLogs\FolderPermissionLog.csv"
$factualCSVOutput = "E:\rezultat\rezultatiWazuhFolder\FactualBruteForceWazuhFolder.csv"
$WazuhCsvOutput = "E:\rezultat\rezultatiWazuhFolder\WazuhBruteForceFolder.csv"

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
function Get-WazuhParsedFsData {
    param($data)
    $dataGroup = $data|Group-Object -Property "_source.data.win.system.eventID"
    $wazuhFolderCreate = $dataGroup.Where({$_.Name -eq 11}).Group
    $Wazuh4670 = $dataGroup.Where({$_.Name -eq 4670}).Group

    $Wazuh4670 = $Wazuh4670|ForEach-Object {
    $FullPath = $_."_source.data.win.eventdata.objectName".replace("\\","\")
    $object = ($_."_source.data.win.eventdata.newSd"|ConvertFrom-SddlString).RawDescriptor.DiscretionaryAcl
    ForEach($o in $object){
        if($o.SecurityIdentifier.value -in $builtinSID){
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

    $wazuhFolderCreate = $wazuhFolderCreate|ForEach-Object {
    $createdFolder = $_."_source.data.win.eventdata.targetFilename".replace("\\","\")
    if($_."_source.data.win.eventdata.ruleName" -eq "ShareCreated"){
            [pscustomobject]@{
                FullPath = $createdFolder
            }
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
    

    $Wazuh4670=$Wazuh4670|select $propPermissions 
    $wazuhFolderCreate=$wazuhFolderCreate|select $propCreated

    return ($Wazuh4670 + $wazuhFolderCreate)|sort -Property FullPath
}

function Get-WazuhTimeStats {
    param(
        $data
    )
    $metodaDateTime = {
    return [datetime]$this."_source.timestamp".Replace('@','')
}
    $medodaTimeDIff = {
    $time1 = [datetime]$this."_source.data.win.system.systemTime"
    $time2 = $this.DateTime
    return ($time2 - $time1).TotalSeconds
    }

    $data|ForEach-Object {
        $_|Add-Member -MemberType ScriptProperty -name 'DateTime' -Value $metodaDateTime -Force
        $_|Add-Member -MemberType ScriptProperty -Name 'DateTimeDiff' -Value $medodaTimeDIff -Force
    }

    $stats = $data|Measure-Object -Property DateTimeDiff -AllStats

    $minimum = $data|where {$_.DateTimeDiff -eq ($stats.Minimum)}
    $minimumSystemTime = ([datetime]$minimum."_source.data.win.system.systemTime").Ticks
    $minimumWazuhTime = $minimum.DateTime.Ticks
    $minimum."_source.timestamp"
    $stats
    Write-Host "minimalno vrijeme u Tikovima WIN OS: $minimumSystemTime
minimalno vrijeme u Tikovima Wazuh: $minimumWazuhTime
Wazuh vrijeme: $($minimum."_source.timestamp")`n" -ForegroundColor Green
    
}

#funkcija je portrebna jer pri logiranju Factual Logsa nismo uračunali sid
function Get-GroupSIDNameHashTable {
    param ($ADlogPATH)
    $hashGrupe = @{}
    $data = Import-Csv -Delimiter * -Path $ADlogPATH
    $grupe = $data|where {$_.created -eq 'True' -and $_.ADObjectType -eq 'Group'}
    $grupe.ForEach({$hashGrupe.Add($_.SID,"DOMENAZAPIS\$($_.samaccountname)")})
    return $hashGrupe
}

$hashGrupe =  Get-GroupSIDNameHashTable -ADlogPATH $dcLogs
$hashBuilitnUsers = @{
    "S-1-5-32-544"="BUILTIN\Administrators"
    "S-1-5-32-545"="BUILTIN\Users"
    "S-1-3-0"="CREATOR OWNER"
    "S-1-5-18"="NT AUTHORITY\SYSTEM"
}

$FSlogsLista = [System.Collections.ArrayList]@()
$items = Get-ChildItem -Path "E:\LogoviBruteForcing\WAZUH\bruteForsingUpdate\fs"
$items|ForEach-Object {
    $d = import-csv -Path $_.FullName
    [void]$FSlogsLista.Add($d)
}
$data = $FSlogsLista.ForEach({$_})

#$data = Import-Csv -Path $WazuhLogsRaw
Get-WazuhTimeStats -data $data


$wazuhFSdata = Get-WazuhParsedFsData -data $data
$factualFSLogs = ParseFactualFolderLogs

$wazuhFSdata|ConvertTo-Csv -Delimiter * -QuoteFields s|Out-File -FilePath $WazuhCsvOutput
$factualFSLogs|ConvertTo-Csv -Delimiter * -QuoteFields s|Out-File -FilePath $factualCSVOutput

$factualFSLogs|where {$_.Renamed -eq 'True'}