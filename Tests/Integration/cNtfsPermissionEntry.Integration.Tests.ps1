#requires -Version 4.0 -Modules Pester

$Global:DSCModuleName   = 'cNtfsAccessControl'
$Global:DSCResourceName = 'cNtfsPermissionEntry'

#region Header

$ModuleRoot = Split-Path -Path $Script:MyInvocation.MyCommand.Path -Parent | Split-Path -Parent | Split-Path -Parent

if (
    (-not (Test-Path -Path (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests') -PathType Container)) -or
    (-not (Test-Path -Path (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -PathType Leaf))
)
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests'))
}
else
{
    & git @('-C', (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests'), 'pull')
}

Import-Module -Name (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force

$TestEnvironment = Initialize-TestEnvironment -DSCModuleName $Global:DSCModuleName -DSCResourceName $Global:DSCResourceName -TestType Integration

#endregion

# Begin Testing
try
{
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($Global:DSCResourceName).Config.ps1"
    . $ConfigFile

    # Create temporary directory
    $TempDirectory = New-Item -Path $TestParameters.Path -ItemType Directory -Force -Verbose
    $Acl = $TempDirectory.GetAccessControl()
    $Acl.SetAccessRuleProtection($false, $false)
    $Acl.Access.Where({-not $_.IsInherited}).ForEach({[Void]$Acl.RemoveAccessRule($_)})
    [System.IO.Directory]::SetAccessControl($TempDirectory.FullName, $Acl)

    #region Integration Tests

    Describe "$($Global:DSCResourceName)_Integration" {

        #region Default Tests

        $ConfigurationName = "$($Global:DSCResourceName)_Config"

        It 'should compile without throwing' {
            {
                Invoke-Expression -Command ('{0} -OutputPath "{1}"' -f $ConfigurationName, $TestEnvironment.WorkingFolder)
                Start-DscConfiguration -Path $TestEnvironment.WorkingFolder -ComputerName localhost -Force -Verbose -Wait
            } | Should Not Throw
        }

        It 'should be able to call Get-DscConfiguration without throwing' {
            {
                Get-DscConfiguration -Verbose -ErrorAction Stop
            } | Should Not Throw
        }

        #endregion

        It 'should have set the resource and all the parameters should match' {
            $Current = Get-DscConfiguration | Where-Object {$_.ConfigurationName -eq $ConfigurationName}
            $Current.Ensure    | Should Be $TestParameters.Ensure
            $Current.Path      | Should Be $TestParameters.Path
            $Current.Principal | Should Be $TestParameters.Principal
        }

    }

    #endregion
}
finally
{
    #region Footer

    Restore-TestEnvironment -TestEnvironment $TestEnvironment

    #endregion

    # Remove temporary directory
    if ($TempDirectory)
    {
        Remove-Item -Path $TempDirectory.FullName -Force -Recurse -Verbose
    }
}
