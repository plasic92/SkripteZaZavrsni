function Get-ApiUsers ([int]$broj){
    $url="https://randomuser.me/api/?results=${broj}&nat=gb,us&inc=phone,name"
    $RandosmUsers=Invoke-RestMethod -Method Get -Uri $url
    return $RandosmUsers.results
}

function New-UserSamAccountName($ime, $prezime){
    $inicijal=$ime.ToLower()[0]
    $prezimeMalo=$prezime.ToLower()
    return $inicijal + $prezimeMalo
}

function New-UserFQDN{
    param(
        $ime,
        $prezime,
        $domena = "domenazapis.local"   
    )
    return "${ime}.${prezime}@${domena}"
   # return $ime + '.' + $prezime + $domena
}

function Remove-SpecialChars($brojMoba){
    $chars=("-","(",")"," ")
    $buff=$brojMoba
    foreach($char in $chars){
        $temp=$buff.replace("$($char)","")
        $buff=$temp 
    }
    $buff="+"+$buff
    return $buff
}


function New-UserObjectFromApiUsers {
    param(
        [object[]]$user,
        $domena = 'domenazapis.local'
    )
    $userObjekt = $user|ForEach-Object {
        $mobile = Remove-SpecialChars $_.phone
        $firstname = $_.name.First
        $lastname = $_.name.Last
        $mail = New-UserFQDN -ime $firstname -prezime $lastname
        $samAccountName  = New-UserSamAccountName -ime $firstname -prezime $lastname
        $UserPrincipalName = $samAccountName + '@' + $domena
        [PSCustomObject]@{
            FirstName = $firstname
            LastName = $lastname
            Name = "${firstname} ${lastname}"
            Mobile = $mobile
            #Mail = $mail
            samAccountName = $samAccountName
            #UserPrincipalName = $UserPrincipalName
        }
    }
    return $userObjekt
}

#možda nazvati New-ADOrganizationalUnitPopulation
function New-ADOrganizationalUnitPopulation {
    param(
        [object[]]$korisnici,
        $adPath,
        $pass = $Global:password
    )
    #$count = $korisnici.count
    foreach($korisnik in $korisnici){
        $splat = @{
            Name = $korisnik.Name
            GivenName = $korisnik.FirstName
            Surname = $korisnik.LastName
            MobilePhone = $korisnik.Mobile
            SamAccountName = $korisnik.samAccountName
            UserPrincipalName = $korisnik.UserPrincipalName
            EmailAddress = $korisnik.Mail
            Path = $adPath
            AccountPassword = $pass
        }
        $DistinguishedName = "CN={0},{1}" -f $korisnik.Name,$adPath
        try{
            New-ADUser @splat -Confirm:$false -Enabled $true  -ErrorAction Stop
            write-host 
            New-Log -ADObject -LogPath $Global:ADLogPathCSV -samAccountName $splat['SamAccountName'] -created $true -ADObjectType 'User' -DistinguishedName $DistinguishedName
        }catch{
            #možda napraviti fukciju koja će se izvršiti ako već postoji korisnik sa isim usernameom
            #funk -user $korinsik -pass $pass -adPath $adPath
            $_
        }
    }
}

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

function New-ADSecurityGroupACLDescritpion {
    param(
        [object]$keyValueFileSystemRights,
        $ou,
        [switch]$sleep,
        [int]$sleepMiliseconds = 350
    )
    
    $keys = $keyValueFileSystemRights.Keys|Sort-Object
    $GroupScope=@('Global','DomainLocal','Universal')
    foreach($key in $keys){
        $name = "Grupa_$key"
        $splat = @{
            Name=$name
            SamAccountName=$name
            Description=$keyValueFileSystemRights[$key].ToString()
            Path=$Ou
            GroupScope=$($GroupScope|Get-Random)
            GroupCategory ='Security'
        }

        $DistinguishedName = "CN={0},{1}" -f $name,$ou
        try{
            New-ADGroup @splat -ErrorAction Stop 
            New-Log -ADObject -LogPath $Global:ADLogPathCSV -samAccountName $splat['SamAccountName'] -created $true -ADObjectType 'Group' -GroupScope $splat['GroupScope'] -DistinguishedName $DistinguishedName
        }catch{}

        #$splat
        if($sleep){
            #Write-Output "spavam..."
            Start-Sleep -Milliseconds $sleepMiliseconds
        }
    }   
}

#možda promjenitio umjesdto ou staviti grupe za param
#ime staviti na New-FolderNamedAfterAccessControlFileSystemAccessRule
function New-FolderNamedAfterAccessControlFileSystemAccessRule{
    param(
        $grupe,
        $rootPath,
        [switch]$sleep,
        [int]$sleepMiliseconds = 350,
        [string]$domena = 'domenazapis'
    )

    
    $max = $grupe.Count
    $count = 1
    foreach($grupa in $grupe){
        $GroupName = $grupa.Description
        $folderPath = "${rootPath}\${GroupName}"
        $groupSamAccountName = $grupa.SamAccountName
        #kreiranje Mape
        New-Item -Name $GroupName -ItemType Directory -Path $rootPath
        New-Log -Folder -LogPath $Global:FolderLogPathCSV -created $true -FolderPath $folderPath 
        $acl = get-acl -Path $folderPath -Audit
        #dodavanje ACL-a   
        $AccessRule = [System.Security.AccessControl.FileSystemAccessRule]::new("${domena}\${groupSamAccountName}",$GroupName,"Allow")
        $acl.SetAccessRule($AccessRule)
        #dodavanje ACL-a na mapu
        $acl | Set-Acl -Path $folderPath
        New-Log -FolderPermission -LogPath $Global:FolderPermissionLogPathCSV -added $true -FolderPath $folderPath -FileSystemAccessRule $acl.Access #-$grupa.sid.value možda staviti sid?
        if($sleep){
            Start-Sleep -Milliseconds $sleepMiliseconds
        }
        
        Write-Progress -Activity "$($count)/$($max)"
        $count++
        
    }
}


function Add-MembersToRandomGroup {
    param(
        [object[]]$users,
        [object[]]$grupe,
        [int]$numUsers = 10
    )
    foreach($grupa in $grupe){
        $members = $users|Get-Random -Count $numUsers 
        Add-ADGroupMember -Identity $grupa -Members $members -Confirm:$false 
        $members.foreach({
            New-Log -ADObject -LogPath $Global:ADLogPathCSV -samAccountName $_.samAccountName -added $true -ADObjectType $_.ObjectClass -inGroup $grupa.samAccountName -DistinguishedName $_.DistinguishedName -SID $_.SID.value -GroupScope $grupa.GroupScope -inGroupSID $grupa.sid.value
        })
    }
}

function Remove-MembersFromRandomGroup {
    param(
        [object[]]$grupe,
        [int]$minCount = 1,
        [int]$maxCount = 4
    )
    foreach($grupa in $grupe){
        $members = Get-ADGroupMember -Identity $grupa 
        $removeMembers = $members|Get-Random -Count (Get-Random -Minimum $minCount -Maximum $maxCount)
        Remove-ADGroupMember -Identity $grupa -Members $removeMembers -Confirm:$false 
        $removeMembers.foreach({
            New-Log -ADObject -logpath $Global:ADLogPathCSV -samAccountName $_.samAccountName -removed $true -ADObjectType $_.ObjectClass  -inGroup $grupa.samAccountName -DistinguishedName $_.DistinguishedName -SID $_.sid.value -GroupScope $grupa.GroupScope -inGroupSID $grupa.sid.value
        })
    }
}

function Rename-RandomFolder {
    param(
        [string]$folderPath,
        [int]$minObjects=5,
        [int]$maxObjects=10,
        [switch]$Delete
    )
    $folderObjects = Get-ChildItem -Path $folderPath
    $folderi = Get-Random -InputObject $folderObjects -Count (Get-Random -Minimum $minObjects -Maximum $maxObjects)
    if($Delete){
        $folderi.ForEach({
            $path= $_.FullName
            Remove-Item -Path $path -Confirm:$false
            New-Log -Folder -LogPath $Global:FolderLogPathCSV -FolderPath $path -delited $true

        })
    }else{
        $folderi.ForEach({
            $parentPath = $_.Parent.fullname
            $path= $_.FullName
            $name = $_.Name.Split("_")[-1]
            $newName = ("RENAMED_$(Get-Random)_" + $name)
            Rename-Item -Path $path -NewName $newName -Confirm:$false
            New-Log -Folder -LogPath $Global:FolderLogPathCSV -FolderPath $path -renamed $true -NewFolderPath "${parentPath}\${newName}"
        })
    }
}

function New-Log {
    param(
        [switch]$ADObject,
        [switch]$Folder,
        [switch]$FolderPermission,
        [string]$LogPath,
        [string]$ADObjectType,
        [string]$GroupScope,
        [string]$inGroup,
        [string]$DistinguishedName,
        [string]$SID,
        [string]$inGroupSID,
        [string]$samAccountName,
        [string]$FolderPath,
        [string]$NewFolderPath,
        [object[]]$FileSystemAccessRule,
        [bool]$created,
        [bool]$delited,
        [bool]$disabled,
        [bool]$renamed,
        [bool]$removed,
        [bool]$added,
        [string]$logTime = [datetime]::now.ToString("yyyy-MM-dd HH:mm:ss.fffffff")
    )


    $ADObjectHeader = "SamAccountName*Created*Delited*Disabled*Added*Removed*ADObjectType*inGroup*GroupScope*DistinguishedName*SID*inGroupSID*LogTime`n"
    $FolderHeader = "FolderPath*Created*Delited*Renamed*NewFolderPath*LogTime`n"
    $FolderPermissionHeader = "FullPath*Removed*Added*FileSystemRights*AccessControlType*IdentityReference*IsInherited*LogTime`n"
    if($ADObject){
        if(-not (([System.IO.FileInfo]$LogPath).Exists)){
            New-Item -Path $LogPath  -ItemType File -Value $ADObjectHeader
        }
        $string = "{0}*{1}*{2}*{3}*{4}*{5}*{6}*{7}*{8}*{9}*{10}*{11}*{12}" -f`
            $samAccountName,[bool]$created,[bool]$delited,[bool]$disabled,[bool]$added,[bool]$removed,$ADObjectType,$inGroup,$GroupScope,$DistinguishedName,$SID,$inGroupSID,$logTime
        Out-File -FilePath $LogPath -Encoding utf8 -Append -InputObject $string
        #$string
    }

    if($Folder){
        if(-not (([System.IO.FileInfo]$LogPath).Exists)){
            New-Item -Path $LogPath  -ItemType File -Value $FolderHeader
        }
        $string = "{0}*{1}*{2}*{3}*{4}*{5}" -f`
            $FolderPath,[bool]$created,[bool]$delited,[bool]$renamed,$NewFolderPath,$logTime
        Out-File  -FilePath $LogPath -Encoding utf8 -Append -InputObject $string 
        #$string
    }

    if($FolderPermission){
        if(-not (([System.IO.FileInfo]$LogPath).Exists)){
            New-Item -Path $LogPath -ItemType File -Value $FolderPermissionHeader
        }
        $accesList = @()
        $FileSystemAccessRule|ForEach-Object{
            $string = "{0}*{1}*{2}*{3}*{4}*{5}*{6}*{7}" -f`
                $FolderPath,[bool]$removed,[bool]$added,$_.FileSystemRights.ToString(),$_.AccessControlType.ToString(),$_.IdentityReference.value,[bool]$_.IsInherited,$logTime
            $accesList += $string
            #Out-File -FilePath $LogPath -Encoding utf8 -Append -InputObject $string
            #$string
        }
        Out-File -FilePath $LogPath -Encoding utf8 -Append -InputObject $accesList
    }
}

############____MAIN____#################################

$Global:ADLogPathCSV = "C:\Users\Administrator.domenazapis\logovi\ADLog.csv"
$Global:FolderLogPathCSV = "C:\Users\Administrator.domenazapis\logovi\FolderLog.csv"
$Global:FolderPermissionLogPathCSV = "C:\Users\Administrator.domenazapis\logovi\FolderPermissionLog.csv"
$Global:password=ConvertTo-SecureString -String 'Pa$$w0rd' -AsPlainText -Force


$UserOU= "OU=KorisniciZaLogiranje,DC=domenazapis,DC=local"
$GroupOU = "OU=GrupeZaLogiranje,DC=domenazapis,DC=local"
$FileServerRootPath = "C:\share\ZaLogiranje"

$createNumUsers = 1000
#$createNumGroups = 100
$randGroupCount = 250

$addMembersCount = 50
$removeMembersMinCount = 25
$removeMembersMaxCount = 35

$renameRandomFolderMinCount = 250
$renameRandomFolderMaxCount = 300

$DisableUserCount = 200
$DeleteUserCount = 150
$DeleteGroupsCount = 1000


#kreiranje korisnika
#$user = get-apiUsers -broj $createNumUsers 


$objectUsers =$data #New-UserObjectFromApiUsers -user $user

#$objectUsers|ConvertTo-Csv -Delimiter * 
#kriranje nesto....
$keyValueFileSystemRights = New-SecurityAccessControlFileSystemRightsCollections #-maxAccessControllInt $createNumGroups

#početak generiranja logova
$startLogTime = Get-Date
$sw = [System.Diagnostics.Stopwatch]::StartNew()

#dodavanje korisnika unutar AD-a
New-ADOrganizationalUnitPopulation -korisnici $objectUsers -adPath $UserOU 

#kreiranje keyValueFileSystemRights objekta i grupa na AD-u
New-ADSecurityGroupACLDescritpion -ou $GroupOU -keyValueFileSystemRights $keyValueFileSystemRights #-sleep -sleepMiliseconds 1000

$grupe = Get-ADGroup -Filter * -SearchBase $GroupOU -Properties description,member 

#kreiranje foldera na fajlserveru i dodavnj prava za grupe
New-FolderNamedAfterAccessControlFileSystemAccessRule -grupe $grupe -rootpath $FileServerRootPath #-sleep -sleepMiliseconds 1000

#dodavanje i  korisnika u nasumične grupe
$randomGrupe = $grupe|Get-Random -Count $randGroupCount
$korisnici = Get-ADUser -Filter * -SearchBase $UserOU 
Add-MembersToRandomGroup -users $korisnici -grupe $randomGrupe -numUsers $addMembersCount
#micanje korisnika iz grupa
Remove-MembersFromRandomGroup -grupe $randomGrupe -minCount $removeMembersMinCount -maxCount $removeMembersMaxCount

#brisanje i preimenovanje foldera
Rename-RandomFolder -folderPath $FileServerRootPath  -minObjects $renameRandomFolderMinCount -maxObjects $renameRandomFolderMaxCount
Rename-RandomFolder -folderPath $FileServerRootPath  -minObjects $renameRandomFolderMinCount -maxObjects $renameRandomFolderMaxCount -delete

#disable User
$korisnici|get-random -Count $DisableUserCount|ForEach-Object {
    Disable-ADAccount -Identity $_  -Confirm:$false
    New-Log -ADObject -LogPath $Global:ADLogPathCSV -disabled $true -ADObjectType  $_.ObjectClass -samAccountName $_.samaccountname -DistinguishedName $_.DistinguishedName -SID $_.SID.value
}

#remove user
$korisnici|get-random -Count $DeleteUserCount|ForEach-Object {
    Remove-ADObject -Identity $_ -Confirm:$false
    New-Log -ADObject -LogPath $Global:ADLogPathCSV -delited $true -ADObjectType $_.ObjectClass  -samAccountName $_.samaccountname -DistinguishedName $_.DistinguishedName -SID $_.SID.value
}

#delite groups
$grupe|Get-Random -Count $DeleteGroupsCount|ForEach-Object {
    if([string]::IsNullOrEmpty($_.member)){
        Remove-ADGroup -Identity $_ -Confirm:$false
        New-Log -ADObject -LogPath $Global:ADLogPathCSV -delited $true -ADObjectType $_.ObjectClass -samAccountName $_.samaccountname -DistinguishedName $_.DistinguishedName -GroupScope $_.GroupScope -SID $_.SID.value
    }
}

$sw.stop()

[timespan]$sw.Elapsed
$startLogTime + $sw.Elapsed
$EndLogTime = $startLogTime.AddSeconds($sw.Elapsed.Seconds)

Write-Host -ForegroundColor Green "Skripta započeta:$startLogTime`nSkripta završena:$($startLogTime + $sw.Elapsed)`nVrijeme trajanja:$($sw.Elapsed.Minutes):$($sw.Elapsed.Seconds)"
