
configuration Sample_cNtfsPermissionsInheritance
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName cNtfsAccessControl

    File TestDirectory
    {
        Ensure = 'Present'
        DestinationPath = 'C:\TestDirectory'
        Type = 'Directory'
    }

    cNtfsPermissionsInheritance DisableInheritance
    {
        Path = 'C:\TestDirectory'
        Enabled = $false
        PreserveInherited = $true
        DependsOn = '[File]TestDirectory'
    }
}

Sample_cNtfsPermissionsInheritance -OutputPath "$Env:SystemDrive\Sample_cNtfsPermissionsInheritance"

Start-DscConfiguration -Path "$Env:SystemDrive\Sample_cNtfsPermissionsInheritance" -Force -Verbose -Wait

Get-DscConfiguration
