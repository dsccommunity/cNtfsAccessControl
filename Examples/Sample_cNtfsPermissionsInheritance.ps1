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

    File TestDirectory
    {
        Ensure          = 'Present'
        DestinationPath = 'C:\TestDirectory'
        Type            = 'Directory'
    }

    # Disable permissions inheritance
    cNtfsPermissionsInheritance DisableInheritance
    {
        Path              = 'C:\TestDirectory'
        Enabled           = $false
        PreserveInherited = $true
        DependsOn         = '[File]TestDirectory'
    }
}

Sample_cNtfsPermissionsInheritance -OutputPath "$Env:SystemDrive\Sample_cNtfsPermissionsInheritance"

Start-DscConfiguration -Path "$Env:SystemDrive\Sample_cNtfsPermissionsInheritance" -Force -Verbose -Wait

Get-DscConfiguration
