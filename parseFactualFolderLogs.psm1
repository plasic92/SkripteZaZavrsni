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
