#requires -Version 4.0 -Modules CimCmdlets, Pester

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

$TestEnvironment = Initialize-TestEnvironment -DSCModuleName $Global:DSCModuleName -DSCResourceName $Global:DSCResourceName -TestType Unit

#endregion

# Begin Testing
try
{
    #region Unit Tests

    InModuleScope $Global:DSCResourceName {

        #region Helper Functions

        function Set-NewTempFileAcl
        {
            <#
            .SYNOPSYS
                Creates temporary files for unit testing of the cNtfsPermissionEntry DSC resource.
            .DESCRIPTION
                The Set-NewTempFileAcl function creates temporary files and performs the following actions on them:
                - Disables NTFS permissions inheritance.
                - Removes all permission entries.
                - Grants Full Control permission to the calling user to ensure the file can be removed later.
                - Optionally adds additional permission entries.
            #>
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory = $false)]
                [ValidateNotNullOrEmpty()]
                [String]
                $Path = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetRandomFileName())),

                [Parameter(Mandatory = $false)]
                [System.Security.AccessControl.FileSystemAccessRule[]]
                $AccessRulesToAdd,

                [Parameter(Mandatory = $false)]
                [Switch]
                $PassThru
            )

            try
            {
                $File = New-Item -Path $Path -ItemType File -Force -ErrorAction Stop -Verbose:$VerbosePreference
                $Acl = $File.GetAccessControl()

                $Acl.SetAccessRuleProtection($true, $false)
                $Acl.Access.ForEach({[Void]$Acl.RemoveAccessRule($_)})

                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $Acl.AddAccessRule((New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $CurrentUser, 'FullControl', 'Allow'))

                if ($PSBoundParameters.ContainsKey('AccessRulesToAdd'))
                {
                    $AccessRulesToAdd.ForEach({$Acl.AddAccessRule($_)})
                }

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

            Context 'Expected behavior' {

                $ContextParameters = @{
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AccessControlInformation = @(
                        New-CimInstance -ClientOnly -Namespace 'root/Microsoft/Windows/DesiredStateConfiguration' `
                            -ClassName 'cNtfsAccessControlInformation' -Property @{FileSystemRights = 'Modify'}
                    )
                }

                Set-NewTempFileAcl -Path $ContextParameters.Path -AccessRulesToAdd @(
                    New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                        -ArgumentList $ContextParameters.Principal, 'Modify', 'Allow'
                )

                $Result = Get-TargetResource @ContextParameters

                It 'should return AccessControlInformation' {
                    $Result.AccessControlInformation.Count | Should Be $ContextParameters.AccessControlInformation.Count
                }

                It 'should return Ensure' {
                    $Result.Ensure -in @('Absent', 'Present') | Should Be $true
                }

                It 'should return Path' {
                    $Result.Path | Should Be $ContextParameters.Path
                }

                It 'should return Principal' {
                    $Result.Principal | Should Be $ContextParameters.Principal
                }

            }

            Context 'Permission Entry is Absent' {

                $ContextParameters = @{
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AccessControlInformation = @(
                        New-CimInstance -ClientOnly -Namespace 'root/Microsoft/Windows/DesiredStateConfiguration' `
                            -ClassName 'cNtfsAccessControlInformation' -Property @{FileSystemRights = 'Modify'}
                    )
                }

                Set-NewTempFileAcl -Path $ContextParameters.Path -AccessRulesToAdd @(
                    New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                        -ArgumentList $ContextParameters.Principal, 'ReadAndExecute', 'Allow'
                )

                It 'should return Ensure set Absent' {
                    $Result = Get-TargetResource @ContextParameters
                    $Result.Ensure | Should Be 'Absent'
                }

            }

            Context 'Permission Entry is Present' {

                $ContextParameters = @{
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AccessControlInformation = @(
                        New-CimInstance -ClientOnly -Namespace 'root/Microsoft/Windows/DesiredStateConfiguration' `
                            -ClassName 'cNtfsAccessControlInformation' -Property @{FileSystemRights = 'Modify'}
                    )
                }

                Set-NewTempFileAcl -Path $ContextParameters.Path -AccessRulesToAdd @(
                    New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                        -ArgumentList $ContextParameters.Principal, 'Modify', 'Allow'
                )

                It 'should return Ensure set Present' {
                    $Result = Get-TargetResource @ContextParameters
                    $Result.Ensure | Should Be 'Present'
                }

            }

        }

        Describe "$Global:DSCResourceName\Test-TargetResource" {

            Context 'Ensure is Absent and Permission Entry is Absent' {

                $ContextParameters = @{
                    Ensure = 'Absent'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                Set-NewTempFileAcl -Path $ContextParameters.Path

                It 'should return True' {
                    Test-TargetResource @ContextParameters | Should Be $true
                }

            }

            Context 'Ensure is Absent and Permission Entry is Present' {

                $ContextParameters = @{
                    Ensure = 'Absent'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                Set-NewTempFileAcl -Path $ContextParameters.Path -AccessRulesToAdd @(
                    New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                        -ArgumentList $ContextParameters.Principal, 'Modify', 'Allow'
                )

                It 'should return False' {
                    Test-TargetResource @ContextParameters | Should Be $false
                }

            }

            Context 'Ensure is Present and Permission Entry is Present' {

                $ContextParameters = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AccessControlInformation = @(
                        New-CimInstance -ClientOnly -Namespace 'root/Microsoft/Windows/DesiredStateConfiguration' `
                            -ClassName 'cNtfsAccessControlInformation' -Property @{FileSystemRights = 'Modify'}
                    )
                }

                Set-NewTempFileAcl -Path $ContextParameters.Path -AccessRulesToAdd @(
                    New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                        -ArgumentList $ContextParameters.Principal, 'Modify', 'Allow'
                )

                It 'should return True' {
                    Test-TargetResource @ContextParameters | Should Be $true
                }

            }

            Context 'Ensure is Present and Permission Entry is Absent' {

                $ContextParameters = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AccessControlInformation = @(
                        New-CimInstance -ClientOnly -Namespace 'root/Microsoft/Windows/DesiredStateConfiguration' `
                            -ClassName 'cNtfsAccessControlInformation' -Property @{FileSystemRights = 'Modify'}
                    )
                }

                Set-NewTempFileAcl -Path $ContextParameters.Path -AccessRulesToAdd @(
                    New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                        -ArgumentList $ContextParameters.Principal, 'ReadAndExecute', 'Allow'
                )

                It 'should return False' {
                    Test-TargetResource @ContextParameters | Should Be $false
                }

            }

        }

        Describe "$Global:DSCResourceName\Set-TargetResource" {

            Context 'Ensure is Absent' {

                $ContextParameters = @{
                    Ensure = 'Absent'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                Set-NewTempFileAcl -Path $ContextParameters.Path -AccessRulesToAdd @(
                    New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                        -ArgumentList $ContextParameters.Principal, 'Modify', 'Allow'
                )

                It 'should remove permissions' {
                    Test-TargetResource @ContextParameters | Should Be $false
                    Set-TargetResource @ContextParameters
                    Test-TargetResource @ContextParameters | Should Be $true
                }

            }

            Context 'Ensure is Present' {

                $ContextParameters = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AccessControlInformation = @(
                        New-CimInstance -ClientOnly -Namespace 'root/Microsoft/Windows/DesiredStateConfiguration' `
                            -ClassName 'cNtfsAccessControlInformation' -Property @{FileSystemRights = 'Modify'}
                    )
                }

                Set-NewTempFileAcl -Path $ContextParameters.Path -AccessRulesToAdd @(
                    New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                        -ArgumentList $ContextParameters.Principal, 'ReadAndExecute', 'Allow'
                )

                It 'should add permissions' {
                    Test-TargetResource @ContextParameters | Should Be $false
                    Set-TargetResource @ContextParameters
                    Test-TargetResource @ContextParameters | Should Be $true
                }

            }

        }

        Describe "$Global:DSCResourceName\ConvertFrom-FileSystemAccessRule" {

            $DescribeParameters = @{
                Principal = 'BUILTIN\Users'
                AccessControlType = 'Allow'
                FileSystemRights = @('ReadAndExecute', 'Write', 'Synchronize')
            }

            Context 'PropagationFlags has the NoPropagateInherit flag set' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                    $DescribeParameters.Principal,
                    $DescribeParameters.FileSystemRights,
                    @('ContainerInherit', 'ObjectInherit'),
                    'NoPropagateInherit',
                    $DescribeParameters.AccessControlType
                )

                It 'should return NoPropagateInherit set to True' {
                    $Result = ConvertFrom-FileSystemAccessRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance        | Should Be 'ThisFolderSubfoldersAndFiles'
                    $Result.NoPropagateInherit | Should Be $true
                }

            }

            Context 'InheritanceFlags is None and PropagationFlags is None' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                    $DescribeParameters.Principal,
                    $DescribeParameters.FileSystemRights,
                    'None',
                    'None',
                    $DescribeParameters.AccessControlType
                )

                It 'should return Inheritance set to ThisFolderOnly if ItemType is Directory' {
                    $Result = ConvertFrom-FileSystemAccessRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance        | Should Be 'ThisFolderOnly'
                    $Result.NoPropagateInherit | Should Be $false
                }

                It 'should return Inheritance set to None if ItemType is File' {
                    $Result = ConvertFrom-FileSystemAccessRule -ItemType File -InputObject $AccessRule
                    $Result.Inheritance        | Should Be 'None'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is "ContainerInherit, ObjectInherit" and PropagationFlags is None' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                    $DescribeParameters.Principal,
                    $DescribeParameters.FileSystemRights,
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    $DescribeParameters.AccessControlType
                )

                It 'should return Inheritance set to ThisFolderSubfoldersAndFiles' {
                    $Result = ConvertFrom-FileSystemAccessRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance        | Should Be 'ThisFolderSubfoldersAndFiles'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is ContainerInherit and PropagationFlags is None' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                    $DescribeParameters.Principal,
                    $DescribeParameters.FileSystemRights,
                    'ContainerInherit',
                    'None',
                    $DescribeParameters.AccessControlType
                )

                It 'should return Inheritance set to ThisFolderAndSubfolders' {
                    $Result = ConvertFrom-FileSystemAccessRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance        | Should Be 'ThisFolderAndSubfolders'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is ObjectInherit and PropagationFlags is None' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                    $DescribeParameters.Principal,
                    $DescribeParameters.FileSystemRights,
                    'ObjectInherit',
                    'None',
                    $DescribeParameters.AccessControlType
                )

                It 'should return Inheritance set to ThisFolderAndFiles' {
                    $Result = ConvertFrom-FileSystemAccessRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance        | Should Be 'ThisFolderAndFiles'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is "ContainerInherit, ObjectInherit" and PropagationFlags is InheritOnly' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                    $DescribeParameters.Principal,
                    $DescribeParameters.FileSystemRights,
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    $DescribeParameters.AccessControlType
                )

                It 'should return Inheritance set to SubfoldersAndFilesOnly' {
                    $Result = ConvertFrom-FileSystemAccessRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance        | Should Be 'SubfoldersAndFilesOnly'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is ContainerInherit and PropagationFlags is InheritOnly' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                    $DescribeParameters.Principal,
                    $DescribeParameters.FileSystemRights,
                    'ContainerInherit',
                    'InheritOnly',
                    $DescribeParameters.AccessControlType
                )

                It 'should return Inheritance set to SubfoldersOnly' {
                    $Result = ConvertFrom-FileSystemAccessRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance        | Should Be 'SubfoldersOnly'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is ObjectInherit and PropagationFlags is InheritOnly' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                    $DescribeParameters.Principal,
                    $DescribeParameters.FileSystemRights,
                    'ObjectInherit',
                    'InheritOnly',
                    $DescribeParameters.AccessControlType
                )

                It 'should return Inheritance set to FilesOnly' {
                    $Result = ConvertFrom-FileSystemAccessRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance        | Should Be 'FilesOnly'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

        }

        Describe "$Global:DSCResourceName\ConvertTo-FileSystemAccessRule" {

            $DescribeParameters = @{
                Principal = 'BUILTIN\Users'
                AccessControlType = 'Allow'
                FileSystemRights = @('ReadAndExecute', 'Write')
            }

            Context 'Expected behavior' {

                It 'should return all the property values set correctly' {
                    $Result = ConvertTo-FileSystemAccessRule @DescribeParameters -ItemType 'Directory' -Inheritance 'None' -NoPropagateInherit $false
                    $Result.FileSystemRights  | Should Be ([System.Security.AccessControl.FileSystemRights]@($DescribeParameters.FileSystemRights, 'Synchronize'))
                    $Result.AccessControlType | Should Be $DescribeParameters.AccessControlType
                    $Result.IdentityReference | Should Be $DescribeParameters.Principal
                    $Result.IsInherited       | Should Be $false
                    $Result.InheritanceFlags  | Should Be 'None'
                    $Result.PropagationFlags  | Should Be 'None'
                }

            }

            Context 'ItemType is Directory and NoPropagateInherit is False' {

                $ContextParameters = $DescribeParameters.Clone()
                $ContextParameters.Add('ItemType', 'Directory')
                $ContextParameters.Add('NoPropagateInherit', $false)

                It 'Inheritance is Null' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance $null
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is None' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'None'
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderOnly' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'ThisFolderOnly'
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderSubfoldersAndFiles' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'ThisFolderSubfoldersAndFiles'
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderAndSubfolders' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'ThisFolderAndSubfolders'
                    $Result.InheritanceFlags | Should Be 'ContainerInherit'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderAndFiles' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'ThisFolderAndFiles'
                    $Result.InheritanceFlags | Should Be 'ObjectInherit'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is SubfoldersAndFilesOnly' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'SubfoldersAndFilesOnly'
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'InheritOnly'
                }

                It 'Inheritance is SubfoldersOnly' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'SubfoldersOnly'
                    $Result.InheritanceFlags | Should Be 'ContainerInherit'
                    $Result.PropagationFlags | Should Be 'InheritOnly'
                }

                It 'Inheritance is FilesOnly' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'FilesOnly'
                    $Result.InheritanceFlags | Should Be 'ObjectInherit'
                    $Result.PropagationFlags | Should Be 'InheritOnly'
                }

            }

            Context 'ItemType is Directory and NoPropagateInherit is True' {

                $ContextParameters = $DescribeParameters.Clone()
                $ContextParameters.Add('ItemType', 'Directory')
                $ContextParameters.Add('NoPropagateInherit', $true)

                It 'Inheritance is Null' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance $null
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is None' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'None'
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderOnly' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'ThisFolderOnly'
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderSubfoldersAndFiles' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'ThisFolderSubfoldersAndFiles'
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is ThisFolderAndSubfolders' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'ThisFolderAndSubfolders'
                    $Result.InheritanceFlags | Should Be 'ContainerInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is ThisFolderAndFiles' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'ThisFolderAndFiles'
                    $Result.InheritanceFlags | Should Be 'ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is SubfoldersAndFilesOnly' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'SubfoldersAndFilesOnly'
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is SubfoldersOnly' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'SubfoldersOnly'
                    $Result.InheritanceFlags | Should Be 'ContainerInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is FilesOnly' {
                    $Result = ConvertTo-FileSystemAccessRule @ContextParameters -Inheritance 'FilesOnly'
                    $Result.InheritanceFlags | Should Be 'ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

            }

            Context 'ItemType is File' {

                It 'should ignore Inheritance and NoPropagateInherit' {
                    $Result = ConvertTo-FileSystemAccessRule @DescribeParameters -ItemType 'File' -Inheritance 'ThisFolderSubfoldersAndFiles' -NoPropagateInherit $true
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
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

        Describe "$Global:DSCResourceName\Resolve-IdentityReference" {

            It 'should resolve by SID' {
                $Result = Resolve-IdentityReference -Identity 'S-1-5-32-545'
                $Result.Name | Should Be 'BUILTIN\Users'
                $Result.SID  | Should Be 'S-1-5-32-545'
            }

            It 'should resolve by Name' {
                $Result = Resolve-IdentityReference -Identity 'Users'
                $Result.Name | Should Be 'BUILTIN\Users'
                $Result.SID  | Should Be 'S-1-5-32-545'
            }

            It 'should throw if Identity is invalid' {
                {Resolve-IdentityReference -Identity $null} | Should Throw
            }

            It 'should write a non-terminating error if Identity cannot be resolved' {
                Resolve-IdentityReference -Identity 'GFawkes' -ErrorAction SilentlyContinue -ErrorVariable ResultError
                $ResultError.Count | Should Be 2
                $ResultError[1].CategoryInfo.Activity | Should Be 'Write-Error'
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
