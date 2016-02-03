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

    File TestDirectory
    {
        Ensure          = 'Present'
        DestinationPath = 'C:\TestDirectory'
        Type            = 'Directory'
    }

    # Grant a single permission
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

    # Grant multiple permissions at a time
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

    # Revoke all explicit permissions
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

