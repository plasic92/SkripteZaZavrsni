param([int]$RecordID)



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

function Export-ADobjectsChangesToCSV {
    param(
        $fullPath,
        $ADobjectCollection
    )
    if($ADobjectCollection){
        $ADobjectCollection = $ADobjectCollection|ForEach-Object {$_}
        $data = $ADobjectCollection|ConvertTo-csv  -Delimiter *
        if(Test-Path -Path $fullPath){
            $data[2..($data.Count -1)]|Out-File -Encoding utf8 -FilePath $fullPath -Append
        }
        else{
            $data|Out-File -Encoding utf8 -FilePath $fullPath
        }
    }

}

function Write-customADEvents {
    param($eventi)
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


Export-ADobjectsChangesToCSV -fullPath 'C:\Users\Administrator\Desktop\skripte\ADGroupMemberChange.csv' -ADobjectCollection $GroupMemberOperationLista
Export-ADobjectsChangesToCSV -fullPath 'C:\Users\Administrator\Desktop\skripte\ADUserGroupChange.csv' -ADobjectCollection $UserGroupOperationLista

}

#$RecordID = 267931


try{
$log = Get-WinEvent -LogName security -FilterXPath "*[System/EventRecordID=$RecordID]" -ErrorAction Stop
}catch { $_|Out-File -FilePath 'C:\Users\Administrator\Desktop\skripte\greska' -Encoding utf8}
$eventID = $log.id
$filter= @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=$eventID)]]</Select>
  </Query>
</QueryList>
"@


#$bookmark = $log.Bookmark

#$lista = [System.Collections.Generic.List[System.Diagnostics.Eventing.Reader.EventLogRecord]]::new()

$events = $log
#$lista.Add($events)
while ($events){
    Write-customADEvents -eventi $events
    $bookmark = $events[-1].Bookmark
    $events = Get-customEvents -logname "Security" -XMLfilter $filter -reversed $false -bookmark $bookmark
    if($events){
        sleep 3
    }
}
