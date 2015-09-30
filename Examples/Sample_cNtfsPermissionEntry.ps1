
configuration Sample_cNtfsPermissionEntry
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName cNtfsAccessControl

    File TestDirectory
    {
        Ensure = 'Present'
        DestinationPath = 'C:\TestDirectory'
        Type = 'Directory'
    }

    File TestFile
    {
        Ensure = 'Present'
        DestinationPath = 'C:\TestDirectory\TestFile.txt'
        Type = 'File'
        Contents = ''
        DependsOn = '[File]TestDirectory'
    }

    # EXAMPLE 1: Add a single permission entry for a principal.
    # NOTE: If you do not specify the AccessControlInformation property, the default permission entry will be used as the reference entry.
    cNtfsPermissionEntry PermissionEntry1
    {
        Ensure = 'Present'
        Path = 'C:\TestDirectory'
        ItemType = 'Directory'
        Principal = $Env:UserDomain, $Env:UserName -join '\'
        DependsOn = '[File]TestDirectory'
    }

    # EXAMPLE 2: Add a single permission for a principal.
    cNtfsPermissionEntry PermissionEntry2
    {
        Ensure = 'Present'
        Path = 'C:\TestDirectory\TestFile.txt'
        ItemType = 'File'
        Principal = 'BUILTIN\Users'
        AccessControlInformation =
        @(
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'Modify'
            }
        )
        DependsOn = '[File]TestFile'
    }

    # EXAMPLE 3: Add multiple permission entries for a principal.
    cNtfsPermissionEntry PermissionEntry3
    {
        Ensure = 'Present'
        Path = 'C:\TestDirectory'
        ItemType = 'Directory'
        Principal = 'BUILTIN\Administrators'
        AccessControlInformation =
        @(
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'Modify'
                Inheritance = 'ThisFolderOnly'
                NoPropagateInherit = $false
            }
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = 'ThisFolderSubfoldersAndFiles'
                NoPropagateInherit = $false
            }
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'AppendData', 'CreateFiles'
                Inheritance = 'SubfoldersAndFilesOnly'
                NoPropagateInherit = $false
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # EXAMPLE 4: Remove all of the non-inherited permission entries for a principal.
    # NOTE: In case the AccessControlInformation property is specified, it will be ignored.
    cNtfsPermissionEntry PermissionEntry4
    {
        Ensure = 'Absent'
        Path = 'C:\TestDirectory'
        ItemType = 'Directory'
        Principal = 'BUILTIN\Users'
        DependsOn = '[File]TestDirectory'
    }

}

Sample_cNtfsPermissionEntry -OutputPath $Env:Temp

Start-DscConfiguration -Path $Env:Temp -Force -Verbose -Wait

Get-DscConfiguration

