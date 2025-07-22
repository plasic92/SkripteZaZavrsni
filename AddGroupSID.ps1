param($path)
function New-SecurityAccessControlFileSystemRightsCollections {
    param(
        [int]$maxAccessControllInt = [int][System.Security.AccessControl.FileSystemRights]::"FullControl"
    )
    
    $keyValueFileSystemRights=@{}
    for($i = 0;$i -le $maxAccessControllInt;$i++){
        try{
            $keyValueFileSystemRights[$i] = [System.Security.AccessControl.FileSystemRights]$i
            Write-Host -ForegroundColor Green "$($i)/$($maxAccessControllInt)"

        }catch [System.Management.Automation.RuntimeException] {}
    }
    return $keyValueFileSystemRights
}

#$path = "C:\Users\Administrator\Desktop\ADLog.csv"
$prefix = 'Grupa_'
$keyValueFileSystemRights = New-SecurityAccessControlFileSystemRightsCollections

$data = import-Csv -delimiter * -path $path

#sortiramo sve ključeve, da ih možemo indeksirati
$intKljucevi = $keyValueFileSystemRights.keys|ForEach-Object {$_}
[array]::Sort($intKljucevi)

#tražimo izbrisanu grupu, jer kada se grupa briše zapisuje se SID 
#pošto su grupe napravljene uzastopno možemo napraviti konstantu
$grupa = $data|where {$_.Delited -eq $true -and $_.ADObjectType -eq 'group'}|select -First 1

#napraviti funkciju get const
$grupaKey = $grupa.SamAccountName.split("_")[1]
$grupaSID = $grupa.SID.Split("-")[-1]
$domainSID = $grupa.SID.Replace(($grupa.SID.Split("-")[-1]),'')
$grupaIndex = $intKljucevi.IndexOf($grupaKey) 
$const = [math]::Abs($grupaSID - $grupaIndex)

#$grupaIndex + $const

#napraviti funkciju Get-GrupeSID
$count = 0
$broj = $intKljucevi.Count
$GrupeSID = foreach($num in $intKljucevi){
    $index = $intKljucevi.IndexOf($num)
    $imeGrupe = $prefix + [string]$num
    $gSID = $domainSID + [string]($const+$index)
    [PSCustomObject]@{
        GroupName = $imeGrupe
        GroupSID = $gSID
    }
    $count++
    write-host "$count/$broj" -ForegroundColor Green

}

$GrupeSIDHashTable = @{}
foreach($g in $GrupeSID){
    $GrupeSIDHashTable[$g.GroupName] = $g.GroupSID
}
#$GrupeSIDHashTable['Grupa_9']


$newData = $data|ForEach-Object {
    if($_.Created -eq $true -and $_.ADObjectType -eq 'group'){
        $_.SID = $GrupeSIDHashTable[$_.SamAccountName]
        $_
    }else{
        $_
    }
}



$newPath = (get-item -Path $path).PSParentPath + '\NewADLog.csv'
$newData|ConvertTo-Csv -Delimiter *|Out-File -Encoding utf8 -FilePath $newPath





