param([int]$RecordID)

function Get-ISO8601DateString  {
    param(
        [datetime]$datetime,
        [switch]$qoutes
    )
    $data = $datetime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    if($qoutes){
        return Write-Output "'$data'"
    else{return $data}
    }
}

function Get-EventDataNameText {
    param(
        [System.Xml.XmlDocument]$XMLEventObjectDataName,
        [string]$DataName,
        [Switch]$qoutes
    )
    $filterBlock = {
        $PSItem.Name -eq $DataName
    }
    $data = $XMLEventObjectDataName.event.EventData.Data.Where($filterBlock)."#text"
    if($qoutes){
        return Write-Output "'$data'"
    }else{
        return $data
    }
}

function Get-customEvents {
    param(
        $logname,
        $XMLfilter,
        $reversed = $true,
        $bookmark
    )
    $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($logname, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $XMLfilter)
    $query.ReverseDirection = $reversed
    $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query, $bookmark)
    while ($event = $reader.ReadEvent()) {
        $event
    }


}



#$RecordID = 19410

$filter= @"

<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=11)] and EventData[Data[@Name='RuleName']='ShareCreated']]
    </Select>
  </Query>
</QueryList>
"@

try{
$log = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System/EventRecordID=$RecordID]" -ErrorAction Stop
}catch { $_|Out-File -FilePath 'C:\Users\Administrator.DOMENAZAPIS\Desktop\skripte\greska' -Encoding utf8}
#$bookmark = $log.Bookmark
#$mapa = [System.IO.FileInfo]$log.Properties[5].Value
#if(-not [string]::IsNullOrEmpty($mapa.Extension)){exit}

$lista = [System.Collections.Generic.List[System.Diagnostics.Eventing.Reader.EventLogRecord]]::new()

$events = $log
$lista.Add($events)


#$ObjectName = $log.Properties[5].value
while ($events){
    sleep 3
    $bookmark = $events[-1].Bookmark
    $events = Get-customEvents -logname "Security" -XMLfilter $filter -reversed $false -bookmark $bookmark
    if($events){
        $events.ForEach({$lista.Add($_)})
    }
}

#flat list
$event11 = $lista|ForEach-Object {$_}

#$event11[0].Properties[5].Value

$customEventObject = foreach($event in $event11){
    $TimeCreated = $event.TimeCreated.ToString("d.M.yyyy HH:mm:s.fff")
    $TimeReceived = [datetime]::Now.ToString("d.M.yyyy HH:mm:s.fff")
    $ObjectName = $event.Properties[5].Value
    if([string]::IsNullOrEmpty(([System.IO.FileInfo]$ObjectName).Extension)){
        try{
            $object = ([System.IO.FileInfo]$ObjectName).GetAccessControl().Access
            $object|ForEach-Object{ Add-Member -InputObject $_ -MemberType NoteProperty -Name 'FolderPath' -Value $ObjectName}
            $object|ForEach-Object{ Add-Member -InputObject $_ -MemberType NoteProperty -Name 'TimeCreated' -Value $TimeCreated}
            $object|ForEach-Object{ Add-Member -InputObject $_ -MemberType NoteProperty -Name 'TimeReceived' -Value $TimeReceived}
            $object
        }catch{}
    }
}

$putanja = 'C:\Users\Administrator.DOMENAZAPIS\Desktop\skripte\FolderCreate.csv'
$header = '"FolderPath"*"TimeCreated"*"TimeReceived"*"FileSystemRights"*"AccessControlType"*"IdentityReference"*"IsInherited"*"ObjectName"*"InheritanceFlags"*"PropagationFlags"'

$data = $customEventObject|ConvertTo-csv  -Delimiter *
if(Test-Path -Path $putanja){
   $data[2..($data.Count -1)]|Out-File -Encoding utf8 -FilePath $putanja -Append
}else{
    $data|Out-File -Encoding utf8 -FilePath $putanja
}





