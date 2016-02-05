<#
.SYNOPSIS
    Assigning NTFS permissions.
.DESCRIPTION
    This example shows how to use the cNtfsPermissionEntry DSC resource to assign NTFS permissions.
#>

Configuration Sample_cNtfsPermissionEntry
{
    Import-DscResource -ModuleName cNtfsAccessControl
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    File TestDirectory
    {
        Ensure          = 'Present'
        DestinationPath = 'C:\TestDirectory'
        Type            = 'Directory'
    }

    # Create a single permission entry for the specified principal.
    cNtfsPermissionEntry PermissionEntry1
    {
        Ensure    = 'Present'
        Path      = 'C:\TestDirectory'
        ItemType  = 'Directory'
        Principal = 'BUILTIN\Power Users'
        AccessControlInformation =
        @(
            cNtfsAccessControlInformation
            {
                AccessControlType  = 'Allow'
                FileSystemRights   = 'ReadAndExecute'
                Inheritance        = 'ThisFolderSubfoldersAndFiles'
                NoPropagateInherit = $false
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # Create multiple permission entries for the specified principal.
    cNtfsPermissionEntry PermissionEntry2
    {
        Ensure    = 'Present'
        Path      = 'C:\TestDirectory'
        ItemType  = 'Directory'
        Principal = 'BUILTIN\Administrators'
        AccessControlInformation =
        @(
            cNtfsAccessControlInformation
            {
                AccessControlType  = 'Allow'
                FileSystemRights   = 'Modify'
                Inheritance        = 'ThisFolderOnly'
                NoPropagateInherit = $false
            }

            cNtfsAccessControlInformation
            {
                AccessControlType  = 'Allow'
                FileSystemRights   = 'ReadAndExecute'
                Inheritance        = 'ThisFolderSubfoldersAndFiles'
                NoPropagateInherit = $false
            }

            cNtfsAccessControlInformation
            {
                AccessControlType  = 'Allow'
                FileSystemRights   = 'AppendData', 'CreateFiles'
                Inheritance        = 'SubfoldersAndFilesOnly'
                NoPropagateInherit = $false
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # Remove all non-inherited permission entries for the specified principal.
    cNtfsPermissionEntry PermissionEntry3
    {
        Ensure    = 'Absent'
        Path      = 'C:\TestDirectory'
        ItemType  = 'Directory'
        Principal = 'BUILTIN\Users'
        DependsOn = '[File]TestDirectory'
    }
}

Sample_cNtfsPermissionEntry -OutputPath "$Env:SystemDrive\Sample_cNtfsPermissionEntry"

Start-DscConfiguration -Path "$Env:SystemDrive\Sample_cNtfsPermissionEntry" -Force -Verbose -Wait

Get-DscConfiguration
