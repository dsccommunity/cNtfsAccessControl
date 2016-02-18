#requires -Version 4.0 -Modules Pester

$Global:DSCModuleName   = 'cNtfsAccessControl'
$Global:DSCResourceName = 'cNtfsPermissionsInheritance'

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

$TestEnvironment = Initialize-TestEnvironment -DSCModuleName $Global:DSCModuleName -DSCResourceName $Global:DSCResourceName -TestType Unit

#endregion

# Begin Testing
try
{
    InModuleScope -ModuleName $DSCResourceName -ScriptBlock {

        #region Helper Functions

        function Set-NewTempFileAclInheritance
        {
            <#
            .SYNOPSYS
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

                if ($Enabled -eq $true -and $Acl.AreAccessRulesProtected -eq $true)
                {
                    $Acl.SetAccessRuleProtection($false, $false)
                }
                elseif ($Enabled -eq $false -and $Acl.AreAccessRulesProtected -eq $false)
                {
                    $Acl.SetAccessRuleProtection($true, $false)
                }

                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $Acl.AddAccessRule((New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $CurrentUser, 'FullControl', 'Allow'))

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

        #region Pester Tests

        Describe "$Global:DSCResourceName\Get-TargetResource" {

            Context 'Inheritance is enabled' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $true

                It 'should return Enabled set to True' {
                    $Result = Get-TargetResource -Path $Path
                    $Result.Enabled | Should Be $true
                }

            }

            Context 'Inheritance is disabled' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $false

                It 'should return Enabled set to False' {
                    $Result = Get-TargetResource -Path $Path
                    $Result.Enabled | Should Be $false
                }

            }

        }

        Describe "$Global:DSCResourceName\Test-TargetResource" {

            Context 'Inheritance is enabled' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $true

                It 'should return True if Enabled is True' {
                    Test-TargetResource -Path $Path -Enabled $true | Should Be $true
                }

                It 'should return False if Enabled is False' {
                    Test-TargetResource -Path $Path -Enabled $false | Should Be $false
                }

            }

            Context 'Inheritance is disabled' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $false

                It 'should return True if Enabled is False' {
                    Test-TargetResource -Path $Path -Enabled $false | Should Be $true
                }

                It 'should return False if Enabled is True' {
                    Test-TargetResource -Path $Path -Enabled $true | Should Be $false
                }

            }

        }

        Describe "$Global:DSCResourceName\Set-TargetResource" {

            Context 'Enabled is True' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                Set-NewTempFileAclInheritance -Path $Path -Enabled $false

                it 'should enable inheritance' {
                    Test-TargetResource -Path $Path -Enabled $true | Should Be $false
                    Set-TargetResource -Path $Path -Enabled $true
                    Test-TargetResource -Path $Path -Enabled $true | Should Be $true
                }

            }

            Context 'Enabled is False and PreserveInherited is True' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                $File = Set-NewTempFileAclInheritance -Path $Path -Enabled $true -PassThru

                it 'should disable inheritance and convert inherited permissions into explicit permissions' {

                    $DaclBeforeSet = $File.GetAccessControl().Access

                    Test-TargetResource -Path $Path -Enabled $false | Should Be $false
                    Set-TargetResource -Path $Path -Enabled $false -PreserveInherited $true
                    Test-TargetResource -Path $Path -Enabled $false | Should Be $true

                    $DaclAfterSet = $File.GetAccessControl().Access
                    ($DaclBeforeSet.Count - $DaclAfterSet.Count) -le 1 | Should Be $true

                }

            }

            Context 'Enabled is False and PreserveInherited is False' {

                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                $File = Set-NewTempFileAclInheritance -Path $Path -Enabled $true -PassThru

                it 'should disable inheritance and remove inherited permissions' {

                    $DaclBeforeSet = $File.GetAccessControl().Access

                    Test-TargetResource -Path $Path -Enabled $false | Should Be $false
                    Set-TargetResource -Path $Path -Enabled $false -PreserveInherited $false
                    Test-TargetResource -Path $Path -Enabled $false | Should Be $true

                    $DaclAfterSet = $File.GetAccessControl().Access
                    $DaclBeforeSet.Count -gt 1 | Should Be $true
                    $DaclAfterSet.Count -eq 1 | Should Be $true

                }

            }

        }

        Describe "$Global:DSCResourceName\Set-FileSystemAccessControl" {

            $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
            $File = New-Item -Path $Path -ItemType File
            $Acl = $File.GetAccessControl()
            $Acl.AddAccessRule((New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList 'BUILTIN\Users', 'FullControl', 'Allow'))

            It 'should not throw' {
                {Set-FileSystemAccessControl -Path $Path -AclObject $Acl} | Should Not Throw
            }

            It 'should throw if Path is invalid' {
                $Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                {Set-FileSystemAccessControl -Path $Path -AclObject $Acl} | Should Throw
            }

            It 'should throw if AclObject is invalid' {
                {Set-FileSystemAccessControl -Path $Path -AclObject $null} | Should Throw
            }

        }

        #endregion

    }
}
catch
{
    #region Footer

    Restore-TestEnvironment -TestEnvironment $TestEnvironment

    #endregion
}
