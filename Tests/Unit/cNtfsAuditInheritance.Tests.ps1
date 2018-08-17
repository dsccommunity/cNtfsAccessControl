#requires -Version 4.0 -Modules Pester

$Global:DSCModuleName   = 'cNtfsAccessControl'
$Global:DSCResourceName = 'cNtfsAuditInheritance'

#region Header

$ModuleRoot = Split-Path -Path $Script:MyInvocation.MyCommand.Path -Parent | Split-Path -Parent | Split-Path -Parent

if (
    (-not (Test-Path -Path (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests') -PathType Container)) -or
    (-not (Test-Path -Path (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -PathType Leaf))
)
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests'))
}

Import-Module -Name (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $Global:DSCModuleName `
    -DSCResourceName $Global:DSCResourceName `
    -TestType Unit

#endregion

try
{
    #region Unit Tests

    InModuleScope $Global:DSCResourceName {

        #region Helper Functions

        function Set-NewTempFileAclInheritance
        {
            <#
            .SYNOPSIS
                Creates temporary files for unit testing of the cNtfsPermissionsInheritance DSC resource.

            .DESCRIPTION
                The Set-NewTempFileAclInheritance function creates temporary files and performs the following actions on them:
                - Grants Full Control permission to the calling user to ensure the file can be removed later.
                - Optionally disables NTFS permissions inheritance and removes inherited permissions.
            #>
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory = $false)]
                [ValidateNotNullOrEmpty()]
                [String]
                $Path = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetRandomFileName())),

                [Parameter(Mandatory = $false)]
                [Boolean]
                $Enabled = $true,

                [Parameter(Mandatory = $false)]
                [Switch]
                $PassThru
            )

            try
            {
                $File = New-Item -Path $Path -ItemType File -Force -ErrorAction Stop -Verbose:$VerbosePreference
                $Acl = $File.GetAccessControl()

                if ($Enabled -eq $true -and $Acl.AreAuditRulesProtected -eq $true)
                {
                    $Acl.SetAuditRuleProtection($false, $false)
                }
                elseif ($Enabled -eq $false -and $Acl.AreAuditRulesProtected -eq $false)
                {
                    $Acl.SetAuditRuleProtection($true, $false)
                }

                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

                $AuditRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $CurrentUser,
                        'FullControl',
                        'None',
                        'None',
                        'Failure'
                    )

                $Acl.AddAuditRule($AuditRule)

                [System.IO.File]::SetAccessControl($File.FullName, $Acl)

                if ($PassThru)
                {
                    return $File
                }
            }
            catch
            {
                throw
            }
        }

        #endregion

        Describe "$Global:DSCResourceName\Get-TargetResource" {

            Context 'Inheritance is enabled' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $true

                It 'Should return Enabled set to True' {
                    $Result = Get-TargetResource -Path $Path
                    $Result.Enabled | Should Be $true
                }

            }

            Context 'Inheritance is disabled' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $false

                It 'Should return Enabled set to False' {
                    $Result = Get-TargetResource -Path $Path
                    $Result.Enabled | Should Be $false
                }

            }

        }

        Describe "$Global:DSCResourceName\Test-TargetResource" {

            Context 'Inheritance is enabled' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $true

                It 'Should return True if Enabled is True' {
                    Test-TargetResource -Path $Path -Enabled $true | Should Be $true
                }

                It 'Should return False if Enabled is False' {
                    Test-TargetResource -Path $Path -Enabled $false | Should Be $false
                }

            }

            Context 'Inheritance is disabled' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $false

                It 'Should return True if Enabled is False' {
                    Test-TargetResource -Path $Path -Enabled $false | Should Be $true
                }

                It 'Should return False if Enabled is True' {
                    Test-TargetResource -Path $Path -Enabled $true | Should Be $false
                }

            }

        }

        Describe "$Global:DSCResourceName\Set-TargetResource" {

            Context 'Enabled is True' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $false

                It 'Should enable inheritance' {
                    Test-TargetResource -Path $Path -Enabled $true | Should Be $false
                    Set-TargetResource -Path $Path -Enabled $true
                    Test-TargetResource -Path $Path -Enabled $true | Should Be $true
                }

            }

            Context 'Enabled is False and PreserveInherited is True' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                $File = Set-NewTempFileAclInheritance -Path $Path -Enabled $true -PassThru

                It 'Should disable inheritance and convert inherited permissions into explicit permissions' {

                    $DaclBeforeSet = (Get-Acl -Path $File.FullName -Audit).Audit
                    

                    Test-TargetResource -Path $Path -Enabled $false | Should Be $false
                    Set-TargetResource -Path $Path -Enabled $false -PreserveInherited $true
                    Test-TargetResource -Path $Path -Enabled $false | Should Be $true

                    $DaclAfterSet = (Get-Acl -Path $File.FullName -Audit).Audit

                    ($DaclBeforeSet.Count - $DaclAfterSet.Count) -le 1 | Should Be $true

                }

            }

            Context 'Enabled is False and PreserveInherited is False' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                $File = Set-NewTempFileAclInheritance -Path $Path -Enabled $true -PassThru

                It 'Should disable inheritance and remove inherited permissions' {

                    Test-TargetResource -Path $Path -Enabled $false | Should Be $false
                    Set-TargetResource -Path $Path -Enabled $false -PreserveInherited $false
                    Test-TargetResource -Path $Path -Enabled $false | Should Be $true

                }

            }

        }

        Describe "$Global:DSCResourceName\Set-FileSystemAccessControl" {

            $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
            $File = New-Item -Path $Path -ItemType File
            $Acl = $File.GetAccessControl()

            $AuditRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                -ArgumentList @(
                    'BUILTIN\Users',
                    'FullControl',
                    'None',
                    'None',
                    'Failure'
                )

            $Acl.AddAuditRule($AuditRule)

            It 'Should not throw' {
                {Set-FileSystemAccessControl -Path $Path -Acl $Acl} | Should Not Throw
            }

            It 'Should throw if Path is invalid' {
                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                {Set-FileSystemAccessControl -Path $Path -Acl $Acl} | Should Throw
            }

            It 'Should throw if Acl is invalid' {
                {Set-FileSystemAccessControl -Path $Path -Acl $null} | Should Throw
            }

        }

    }

    #endregion
}
finally
{
    #region Footer

    Restore-TestEnvironment -TestEnvironment $TestEnvironment

    #endregion
}
