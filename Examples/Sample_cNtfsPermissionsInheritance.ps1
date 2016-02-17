<#
.SYNOPSIS
    Disable NTFS permissions inheritance.
.DESCRIPTION
    This example shows how to use the cNtfsPermissionsInheritance DSC resource to disable NTFS permissions inheritance.
#>

Configuration Sample_cNtfsPermissionsInheritance
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

    # Disable permissions inheritance.
    cNtfsPermissionsInheritance DisableInheritance
    {
        Path = $TestDirectoryPath
        Enabled = $false
        PreserveInherited = $true
        DependsOn = '[File]TestDirectory'
    }
}

$OutputPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'Sample_cNtfsPermissionsInheritance'
Sample_cNtfsPermissionsInheritance -OutputPath $OutputPath
Start-DscConfiguration -Path $OutputPath -Force -Verbose -Wait
Get-DscConfiguration
