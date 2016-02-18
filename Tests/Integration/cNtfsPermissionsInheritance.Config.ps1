$TestParameters = [PSCustomObject]@{
    Path = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().Guid))
    Enabled = $false
    PreserveInherited = $true
}

Configuration cNtfsPermissionsInheritance_Config
{
    Import-DscResource -ModuleName cNtfsAccessControl

    Node localhost
    {
        cNtfsPermissionsInheritance Test1
        {
            Path = $TestParameters.Path
            Enabled = $TestParameters.Enabled
            PreserveInherited = $TestParameters.PreserveInherited
        }
    }
}
