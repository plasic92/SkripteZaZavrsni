$FSrawLogsPath = "E:\LogoviBruteForcing\LogoviExceded\FSExceded.csv"

$adlogPATH = "E:\LogoviBruteForcing\LogoviExceded\logovi\NewADLog.csv"
$FolderPermissionsPath = "E:\LogoviBruteForcing\LogoviExceded\logovi\FolderPermissionLog.csv"
$FolderLogPath = "E:\LogoviBruteForcing\LogoviExceded\logovi\FolderLog.csv"

$factualCSVOutput = "E:\rezultat\rezultatFortiFolder\FactualBruteForceFortiFolder.csv"
$FortiWindowLogsCsvOutput = "E:\rezultat\rezultatFortiFolder\FortiWindowsBruteForce.csv"
$fortiFIMCSVOutput = "E:\rezultat\rezultatFortiFolder\FortiFIMBruteForce.csv"

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

function Get-XmlObjectEventData {
    param(
        [System.Xml.XmlDocument]$xmlObject,
        [string]$Name
    )
    return $xmlObject.Event.EventData.Data.Where({$_.name -eq $Name})."#text"
}

function Get-FortiSIEMRawLogs {
    param(
        [string]$RawLogsPath,
        [array]$header = @('recievedTime','ip','LogType','RawData')
    )
    $rawData = Get-Content -Raw -Path $RawLogsPath|ConvertFrom-Csv -Header $header
    $eventLogObject = $rawData|ForEach-Object {
    if($_.RawData -match '(?s)\[xml\]=(<Event.+?</Event>)'){
        $xmlObject = [xml]$Matches[1]
        $t = [datetime]$xmlObject.Event.System.TimeCreated.SystemTime
        $rt = ([datetime]$_.recievedTime).ToString("yyyy-MM-dd HH:mm:ss.fffffff")
        $time = $t.ToString("yyyy-MM-dd HH:mm:ss.fffffff")
        $parsedData =  [pscustomobject]@{
            recievedTime = $rt
            EventType = $_.LogType
            logtime = $time
        }
        $xmlProperties = $xmlObject.Event.EventData.Data.name
        $xmlProperties.ForEach({
            Add-Member -InputObject $parsedData  -NotePropertyName $_ -NotePropertyValue (Get-XmlObjectEventData -xmlObject $xmlObject  -Name $_)
        });
        $parsedData
    }else{
        $_
    }
    
    }
    return $eventLogObject
}

function Get-parsedForti4670{
    param($Forti4670)
function Get-MapedSecurityIdentifierValue {
    param(
        $builtiUser = $Global:hashBuilitnUsers,
        $adgrups = $Global:hashGrupe,
        $object
    )
    if($builtiUser.ContainsKey($object.SecurityIdentifier.value)){
        $id = $builtiUser[$object.SecurityIdentifier.value]
    }else{
        $id = $adgrups[$object.SecurityIdentifier.value]
    }
    return $id

}
#$object.SecurityIdentifier.value
$Forti4670|ForEach-Object {
    $FullPath = $_.ObjectName
    $object = ($_.NewSd|ConvertFrom-SddlString).RawDescriptor.DiscretionaryAcl
    $object|ForEach-Object{
        $id = Get-MapedSecurityIdentifierValue -object $_
        [pscustomobject]@{
            FullPath = $FullPath
            FileSystemRights = [System.Security.AccessControl.FileSystemRights]$_.AccessMask
            IdentityReference = $id
            PermissionChange = 'True'
            Created = 'False'
            Deleted = 'False'
            Removed = 'False'
            Renamed = 'False'
            NewFolderPath = 'NoInfo'
            OldFolderPath = 'NoInfo'
        }
    }
}
}

function Get-ParsedSysmom11 {
    param($WindowsData)
    $sysmon11 = $WindowsData.Where({$_.Name -eq 'Win-Sysmon-11-FileCreate' }).group
    $sysmon11|ForEach-Object {
        [PSCustomObject]@{
            FullPath = $_.TargetFilename
            FileSystemRights = ''
            IdentityReference = ''
            PermissionChange = 'False'
            Created = 'True'
            Removed = 'False'
            Renamed = 'False'
            NewFolderPath = 'NoInfo'
            OldFolderPath = 'NoInfo'
        }
    }
}

function Get-FortiTimeStats {
    param($timeData)
    $metodaTimeDelta = {
        $time1 = [datetime]$this.logTime
        $time2 = [datetime]$this.recievedTime
        return ($time2 -$time1).TotalSeconds
    }
    $timeData|ForEach-Object {
        $_|Add-Member -MemberType ScriptProperty -Name 'DateTimeDiff' -Value $metodaTimeDelta -Force
    }

    $stats = $timeData|Measure-Object -Property DateTimeDiff -AllStats

        $minimum = $timeData|where {$_.DateTimeDiff -eq ($stats.Minimum)}
        $minimumSystemTime = ([datetime]$minimum.logtime).Ticks
        $minimumFortiTime = ([datetime]$minimum.recievedTime).Ticks
        $stats
        Write-Host "minimalno vrijeme u Tikovima WIN OS: $minimumSystemTime
minimalno vrijeme u Tikovima Forti: $minimumFortiTime
Forti vrijeme: $($minimum.recievedTime)`n" -ForegroundColor Green
}


function Get-FortiFIMParsedData {
param($dataForti)
$FortiFIMlogs = $dataForti|where {$_.name -like "*FileMon*"}

$FortiLogs = $FortiFIMlogs.group|ForEach-Object {
   $_|Add-Member -MemberType ScriptProperty -Name 'fileName' -Value $metodFortiLog -Force
   $_|Add-Member -MemberType ScriptProperty -Name 'targetUser' -Value $metodFortiLog1 -Force
   $_|Add-Member -MemberType ScriptProperty -Name 'targetFilePermit' -Value $metodFortiLog2 -Force
   [pscustomobject]@{
    LogType = $_.LogType
    FullPath= $_.fileName
    FileSystemRights = $_.targetFilePermit
    IdentityReference = $_.targetUser

    
   }
}

$propAdded = @(
    'FullPath',@{n='FileSystemRights';e={''}},@{n='IdentityReference';e={''}},
    @{n='PermissionChange';e={'False'}},
    @{n='Created';e={'True'}},
    @{n='Deleted';e={'False'}},
    @{n='Removed';e={'False'}},
    @{n='Renamed';e={'False'}},
    'NewFolderPath','OldFolderPath'

)

$propSecurityChange = @(
    'FullPath','FileSystemRights','IdentityReference',
    @{n='PermissionChange';e={'True'}},
    @{n='Created';e={'False'}},
    @{n='Deleted';e={'False'}},
    @{n='Removed';e={'False'}},
    @{n='Renamed';e={'False'}},
    'NewFolderPath','OldFolderPath'
)

$propDeleted = @(
    'FullPath',@{n='FileSystemRights';e={''}},@{n='IdentityReference';e={''}},
    @{n='PermissionChange';e={'False'}},
    @{n='Created';e={'False'}},
    @{n='Deleted';e={'True'}},
    @{n='Removed';e={'False'}},
    @{n='Renamed';e={'False'}},
    @{n='NewFolderPath';e={'NoInfo'}},@{n='OldFolderPath';e={'NoInfo'}}
)

$FolderAdded|select -First 1
#FullPath !C:\share\ZaLogiranje
$FortiFIMgroup = $FortiLogs|Group-Object -Property LogType

$securityChange = $FortiFIMgroup.Where({$_.Name -like "*AO-WUA-FileMon-Added*"}).group.where({$_.FullPath -ne 'C:\share\ZaLogiranje'})
$securityChange = $securityChange|select $propSecurityChange
$FolderAdded = $securityChange.Where({$_.IdentityReference -notlike "*Grupa*"})
$FolderAdded = $FolderAdded|select -Property FullPath|sort -Property FullPath -Unique 
$FolderAdded = $FolderAdded|select $propAdded
$FolderRenamed = $FortiFIMlogs.Where({$_.Name -like "*Renamed*"}).group
$folderDeleted = $FortiFIMgroup.Where({$_.name -eq 'AO-WUA-FileMon-Removed'}).group|select $propDeleted

$FolderRenamed = $FolderRenamed|ForEach-Object{
    if($_.RawData -match '[Old Name]'){
        [pscustomobject]@{
            FullPath = $_.fileName
            FileSystemRights = ''
            IdentityReference = ''
            PermissionChange = 'False'
            Created = 'False'
            Deleted = 'False'
            Removed = 'False'
            Renamed = 'True'
            NewFolderPath = 'NoInfo'
            OldFolderPath = $_.fileName

        }
    }elseif($_.RawData -match '[New Name]'){
        [pscustomobject]@{
            FullPath = ''
            FileSystemRights = ''
            IdentityReference = ''
            PermissionChange = 'False'
            Created = 'False'
            Deleted = 'False'
            Removed = 'False'
            Renamed = 'True'
            NewFolderPath = $_.fileName
            OldFolderPath = 'NoInfo'

        }
    }
}

$allFortiFolderLogs = $securityChange + $FolderAdded +$FolderRenamed + $folderDeleted|sort -Property FullPath

$allFortiFolderLogs
}


function Get_FortiFIMTimeStats {
    param($dataForti)

    $FortiFIMlogs = $dataForti|where {$_.name -like "*FileMon*"}
    $metodaTimeDelta = {
        $time1 = [datetime]$this.logTime
        $time2 = [datetime]$this.recievedTime
        return ($time2 -$time1).TotalSeconds
    }
    $fortiFIMTimeStats = $FortiFIMlogs.group|ForEach-Object {
    $object =  [pscustomobject]@{
        recievedTime = $_.recievedTime
        logTime = [datetime]$_.rawData.split(" ")[0]
    }
    $object|Add-Member -MemberType ScriptProperty -Name 'TimeDiff' -Value $metodaTimeDelta
    $object
    }

    $stats = $fortiFIMTimeStats|Measure-Object -Property TimeDiff -AllStats

    return $stats
}



$metodFortiLog = {
    if($this.RawData -match '\[fileName\]="(.+?)"'){
        $fileName = $Matches[1].Replace("\\","\")
        return $fileName
    }
}

$metodFortiLog1 = {
    if($this.RawData -match '\[targetUser\]="(.+?)"'){
        $targetUser = $Matches[1]
        return $targetUser
    }
}

$metodFortiLog2 = {
    if($this.RawData -match '\[targetFilePermit\]="(.+?)"'){
        $targetFilePermit = $Matches[1]
        return $targetFilePermit
    }
}

function Get-GroupSIDNameHashTable {
    param ($ADlogPATH)
    $hashGrupe = @{}
    $data = Import-Csv -Delimiter * -Path $ADlogPATH
    $grupe = $data|where {$_.created -eq 'True' -and $_.ADObjectType -eq 'Group'}
    $grupe.ForEach({$hashGrupe.Add($_.SID,"DOMENAZAPIS\$($_.samaccountname)")})
    return $hashGrupe
}


$metodaTimeDelta = {
    $time1 = [datetime]$this.logTime
    $time2 = [datetime]$this.recievedTime
    return ($time2 -$time1).TotalSeconds
}


#$folderData = import-csv -Path $folderLog -Delimiter *
#$factualPermissions = Import-Csv -Delimiter * -Path $FoldePrava
$hashGrupe = Get-GroupSIDNameHashTable -ADlogPATH $adlogPATH
$eventLogObject = Get-FortiSIEMRawLogs -RawLogsPath $FSrawLogsPath
$WindowsData = $eventLogObject|Group-Object -Property EventType
$dataForti = $eventLogObject|Group-Object -Property LogType



$Forti4670=$WindowsData.Where({$_.Name -eq 'Win-Security-4670'}).group
$forti4670Parsed = Get-parsedForti4670 -Forti4670 $Forti4670

$sysmon11 = Get-ParsedSysmom11 -WindowsData $WindowsData

$fortiParsedWindowsData = $forti4670Parsed + $sysmon11|sort -Property FullPath
$fortiParsedWindowsData=$fortiParsedWindowsData[0..($fortiParsedWindowsData.count - 7)]

$fortiParsedWindowsData|select -Last 10


$TimeData = $WindowsData.Where({$_.name -eq "Win-Security-4670" -or $_.Name -eq "Win-Sysmon-11-FileCreate"}).group
$TimeDataStats = Get-FortiTimeStats -timeData $TimeData



$fortiFIMParsedData  = Get-FortiFIMParsedData -dataForti $dataForti

Get_FortiFIMTimeStats -dataForti $dataForti

$factualLogs = ParseFactualFolderLogs

$factualLogs|ConvertTo-Csv -Delimiter * -QuoteFields s|Out-File -FilePath $factualCSVOutput
$fortiParsedWindowsData|ConvertTo-Csv -Delimiter * -QuoteFields s|Out-File -FilePath $FortiWindowLogsCsvOutput
#$fortiFIMParsedData|ConvertTo-Csv -Delimiter * -QuoteFields s|Out-File -FilePath $fortiFIMCSVOutput
