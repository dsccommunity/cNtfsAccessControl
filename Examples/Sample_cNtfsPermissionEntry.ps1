<#
.SYNOPSIS
    Assign NTFS permissions.
.DESCRIPTION
    This example shows how to use the cNtfsPermissionEntry DSC resource to assign NTFS permissions.
#>

Configuration Sample_cNtfsPermissionEntry
{
    Import-DscResource -ModuleName cNtfsAccessControl
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $TestDirectoryPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'TestDirectory'

    File TestDirectory
    {
        Ensure = 'Present'
        DestinationPath = $TestDirectoryPath
        Type = 'Directory'
    }

    # Create a single permission entry for the local 'BUILTIN\Users' group.
    cNtfsPermissionEntry PermissionEntry1
    {
        Ensure = 'Present'
        Path = $TestDirectoryPath
        Principal = 'BUILTIN\Users'
        AccessControlInformation = @(
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = 'ThisFolderSubfoldersAndFiles'
                NoPropagateInherit = $false
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # Create multiple permission entries for the 'BUILTIN\Administrators' group.
    cNtfsPermissionEntry PermissionEntry2
    {
        Ensure = 'Present'
        Path = $TestDirectoryPath
        Principal = 'BUILTIN\Administrators'
        AccessControlInformation = @(
            cNtfsAccessControlInformation
            {
                FileSystemRights = 'Modify'
                Inheritance = 'ThisFolderOnly'
            }
            cNtfsAccessControlInformation
            {
                FileSystemRights = 'ReadAndExecute'
                Inheritance = 'ThisFolderSubfoldersAndFiles'
            }
            cNtfsAccessControlInformation
            {
                FileSystemRights = 'AppendData', 'CreateFiles'
                Inheritance = 'SubfoldersAndFilesOnly'
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # Remove all explicit permissions for the 'NT AUTHORITY\Authenticated Users' group.
    cNtfsPermissionEntry PermissionEntry3
    {
        Ensure = 'Absent'
        Path = $TestDirectoryPath
        Principal = 'NT AUTHORITY\Authenticated Users'
        DependsOn = '[File]TestDirectory'
    }
}

$OutputPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'Sample_cNtfsPermissionEntry'
Sample_cNtfsPermissionEntry -OutputPath $OutputPath
Start-DscConfiguration -Path $OutputPath -Force -Verbose -Wait
Get-DscConfiguration
