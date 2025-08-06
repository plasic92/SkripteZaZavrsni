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

function Get-Event4663 {
param(
    $events
)
$time2 = Get-ISO8601DateString -datetime $events[-1].TimeCreated -qoutes
$time1 = Get-ISO8601DateString -datetime $events[0].TimeCreated -qoutes

#[System.Security.AccessControl.FileSystemRights]0x10000 --> Delete
$q = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and 
          Task=12800 and 
          (EventID=4663) and 
          TimeCreated[@SystemTime &gt;=$($time1) and @SystemTime &lt;=$($time2)]] 
          and
          EventData[Data[@Name='AccessMask'] and Data='0x10000']

       ]
    </Select>
  </Query>
</QueryList>
"@

$event4663 = Get-WinEvent -FilterXml $q
return $event4663 
}

function Write-customEvents {
param(
    $event4663
)
$customEventObject = foreach($event in $event4663){
    [PSCustomObject]@{
        TimeReceived = [datetime]::Now.ToString("d.M.yyyy HH:mm:s.fff")
        TimeCreated = $event.TimeCreated.ToString("d.M.yyyy HH:mm:s.fff")
        SID = $event.Properties[0].Value
        UserName = $event.Properties[1].Value
        Domain = $event.Properties[2].Value
        SubjectLogonId = "0x$($event.properties[3].value.ToString("X"))"
        ObjectName = $event.Properties[6].Value
        ProcessName = $event.Properties[11].Value
    }
}

$putanja = 'C:\Users\Administrator.DOMENAZAPIS\Desktop\skripte\logDelete.csv'
$header = '"TimeReceived"*"TimeCreated"*"SID"*"UserName"*"Domain"*"SubjectLogonId"*"ObjectName"*"ProcessName"'

$data = $customEventObject|ConvertTo-csv  -Delimiter *
if(Test-Path -Path $putanja){
   $data[2..($data.Count -1)]|Out-File -Encoding utf8 -FilePath $putanja -Append
}else{
    $data|Out-File -Encoding utf8 -FilePath $putanja
}
}


#$RecordID = 337645


$filterObjectDeleted= @"
    <QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
    *[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and 
    Task = 12800 and (EventID=4660) ]]
    </Select>
  </Query>
</QueryList>
"@

try{
$log = Get-WinEvent -LogName security -FilterXPath "*[System/EventRecordID=$RecordID]" -ErrorAction Stop
}catch { $_|Out-File -FilePath 'C:\Users\Administrator.DOMENAZAPIS\Desktop\skripte\greska' -Encoding utf8}
#$bookmark = $log.Bookmark

#$lista = [System.Collections.Generic.List[System.Diagnostics.Eventing.Reader.EventLogRecord]]::new()

$events = $log
#$lista.Add($events)
while ($events){
    $event4663 = Get-Event4663 -events $events
    Write-customEvents -event4663 $event4663   
    $bookmark = $events[-1].Bookmark
    $events = Get-customEvents -logname "Security" -XMLfilter $filterObjectDeleted -reversed $false -bookmark $bookmark
    if($events){
        sleep 3
    }
}




