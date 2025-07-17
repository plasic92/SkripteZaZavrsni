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



#$RecordID = 267931


$filter= @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4727 or EventID=4728 or EventID=4729 or EventID=4730 or EventID=4731 or EventID=4732 or EventID=4733 or EventID=4734 or EventID=4735 or EventID=4754 or EventID=4756 or EventID=4757 or EventID=4758 or EventID=4720 or EventID=4722 or EventID=4725 or EventID=4726)]]</Select>
  </Query>
</QueryList>
"@

try{
$log = Get-WinEvent -LogName security -FilterXPath "*[System/EventRecordID=$RecordID]" -ErrorAction Stop
}catch { $_|Out-File -FilePath 'C:\Users\Administrator\Desktop\skripte\greska' -Encoding utf8}
#$bookmark = $log.Bookmark

$lista = [System.Collections.Generic.List[System.Diagnostics.Eventing.Reader.EventLogRecord]]::new()

$events = $log
$lista.Add($events)
while ($events){
    sleep 3
    $bookmark = $events[-1].Bookmark
    $events = Get-customEvents -logname "Security" -XMLfilter $filter -reversed $false -bookmark $bookmark
    if($events){
        $events.ForEach({$lista.Add($_)})
    }
}

#flat list
$eventi = $lista|ForEach-Object {$_}



$GroupMemberOperationLista = [System.Collections.Generic.List[object]]::new()
$UserGroupOperationLista = [System.Collections.Generic.List[object]]::new()
#operacija na group memberima i pripadajući eveti
$GroupMemberIDs = @(4728,4732,4756,4729,4733,4757)
foreach($event in $eventi){
    if($GroupMemberIDs.Contains($event.id)){
        $object = [PSCustomObject]@{
            TimeReceived = [datetime]::Now.ToString("d.M.yyyy HH:mm:s.fff")
            TimeCreated = $event.TimeCreated.ToString("d.M.yyyy HH:mm:s.fff")
            MemberName = $event.properties[0].Value
            MemberSid = $event.properties[1].Value
            TargetUserName = $event.properties[2].Value
            TargetSid = $event.properties[4].Value
            EventID = $event.id
        }
        $GroupMemberOperationLista.Add($object)
    }else{
        $object = [PSCustomObject]@{
            TimeReceived = [datetime]::Now.ToString("d.M.yyyy HH:mm:s.fff")
            TimeCreated = $event.TimeCreated.ToString("d.M.yyyy HH:mm:s.fff")
            TargetUserName = $event.properties[0].value
            TargetSid = $event.properties[2].value       
            SubjectUserSid = $event.properties[3].value   
            SubjectUserName = $event.properties[4].value
            EventID = $event.id
        }
        $UserGroupOperationLista.Add($object)
    }
}

if($GroupMemberOperationLista){
    $ADGroupMemberChange = $GroupMemberOperationLista|ForEach-Object {$_}
    $putanja1 = 'C:\Users\Administrator\Desktop\skripte\ADGroupMemberChange.csv'
    $header1 = '"TimeReceived"*"TimeCreated"*"MemberName"*"MemberSid"*"TargetUserName"*"TargetSid"*"EventID"'

    $data = $ADGroupMemberChange|ConvertTo-csv  -Delimiter *
    if(Test-Path -Path $putanja1){
       $data[2..($data.Count -1)]|Out-File -Encoding utf8 -FilePath $putanja1 -Append
    }else{
        $data|Out-File -Encoding utf8 -FilePath $putanja1
    }
}


if($UserGroupOperationLista){
    $ADUserGroupChange = $UserGroupOperationLista|ForEach-Object {$_}
    $putanja2 = 'C:\Users\Administrator\Desktop\skripte\ADUserGroupChange.csv'
    $header2 = '"TimeReceived"*"TimeCreated"*"TargetUserName"*"TargetSid"*"SubjectUserSid"*"SubjectUserName"*"EventID"'

    $data = $ADUserGroupChange|ConvertTo-csv  -Delimiter *
    if(Test-Path -Path $putanja2){
       $data[2..($data.Count -1)]|Out-File -Encoding utf8 -FilePath $putanja2 -Append
    }else{
        $data|Out-File -Encoding utf8 -FilePath $putanja2
    }
}


