#requires -Version 4.0 -Modules Pester, CimCmdlets

$Global:DSCModuleName   = 'cNtfsAccessControl'
$Global:DSCResourceName = 'cNtfsAuditEntry'

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

        function Set-NewTempItemAcl
        {
            <#
            .SYNOPSIS
                Creates a new temporary directory or file and sets its Access Control List (ACL).

            .DESCRIPTION
                The Set-NewTempItemAcl function creates a new temporary directory or file and sets its Access Control List (ACL):
                - Disables NTFS permissions inheritance.
                - Removes all permission entries.
                - Grants Full Control permission to the calling user to ensure the file can be removed later.
                - Optionally adds additional permission entries.
            #>
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory = $false)]
                [ValidateSet('Directory', 'File')]
                [String]
                $ItemType = 'Directory',

                [Parameter(Mandatory = $false)]
                [ValidateNotNullOrEmpty()]
                [String]
                $Path = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetRandomFileName())),

                [Parameter(Mandatory = $false)]
                [System.Security.AccessControl.FileSystemAuditRule[]]
                $AuditRulesToAdd,

                [Parameter(Mandatory = $false)]
                [Switch]
                $PassThru
            )

            try
            {
                $TempItem = New-Item -Path $Path -ItemType $ItemType -Force -ErrorAction Stop -Verbose:$VerbosePreference
                $Acl = $TempItem.GetAccessControl()

                $Acl.SetAuditRuleProtection($true, $false)
                #$Acl.Audit.ForEach({[Void]$Acl.RemoveAuditRule($_)})

                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

                if ($ItemType -eq 'Directory')
                {
                    $DefaultAuditRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $CurrentUser,
                            'FullControl',
                            @('ContainerInherit',
                            'ObjectInherit'),
                            'None',
                            'Failure'
                        )
                }
                else
                {
                    $DefaultAuditRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $CurrentUser,
                            'FullControl',
                            'None',
                            'None',
                            'Sucess'
                        )
                }

                $Acl.AddAuditRule($DefaultAuditRule)

                if ($PSBoundParameters.ContainsKey('AuditRulesToAdd'))
                {
                    $AuditRulesToAdd.ForEach({$Acl.AddAuditRule($_)})
                }

                if ($ItemType -eq 'Directory')
                {
                    [System.IO.Directory]::SetAccessControl($TempItem.FullName, $Acl)
                }
                else
                {
                    [System.IO.File]::SetAccessControl($TempItem.FullName, $Acl)
                }

                if ($PassThru)
                {
                    return $TempItem
                }
            }
            catch
            {
                throw
            }
        }

        #endregion

        Describe "$Global:DSCResourceName\Get-TargetResource" {

            Context 'Permissions exist' {

                $ContextParams = @{
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'ReadAndExecute',
                            @('ContainerInherit', 'ObjectInherit'),
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                $Result = Get-TargetResource @ContextParams

                It 'Should return Ensure set to Present' {
                    $Result.Ensure | Should Be 'Present'
                }

                It 'Should return Path' {
                    $Result.Path | Should Be $ContextParams.Path
                }

                It 'Should return Principal' {
                    $Result.Principal | Should Be $ContextParams.Principal
                }

                It 'Should return AuditRuleInformation' {
                    $Result.AuditRuleInformation.Count | Should Be 3
                }

            }

            Context 'No permissions exist' {

                $ContextParams = @{
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

                $Result = Get-TargetResource @ContextParams

                It 'Should return Ensure set to Absent' {
                    $Result.Ensure | Should Be 'Absent'
                }

                It 'Should return Path' {
                    $Result.Path | Should Be $ContextParams.Path
                }

                It 'Should return Principal' {
                    $Result.Principal | Should Be $ContextParams.Principal
                }

                It 'Should return empty AuditRuleInformation' {
                    $Result.AuditRuleInformation.Count | Should Be 0
                }

            }

        }

        Describe "$Global:DSCResourceName\Test-TargetResource behavior with Ensure set to Absent" {

            Context 'AuditControlInformation is not specified, no permissions exist' {

                $ContextParams = @{
                    Ensure = 'Absent'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

                It 'Should return True' {
                    Test-TargetResource @ContextParams | Should Be $true
                }

            }

            Context 'AuditControlInformation is not specified, permissions exist' {

                $ContextParams = @{
                    Ensure = 'Absent'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'ReadAndExecute',
                            @('ContainerInherit', 'ObjectInherit'),
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should return False' {
                    Test-TargetResource @ContextParams | Should Be $false
                }

            }

            Context 'AuditRuleInformation is specified, no matching permissions exist' {

                $ContextParams = @{
                    Ensure = 'Absent'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AuditRuleInformation = @(

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'ReadAndExecute'
                                Inheritance = 'ThisFolderSubfoldersAndFiles'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'Modify'
                                Inheritance = 'ThisFolderOnly'
                                NoPropagateInherit = $false
                            }

                    )
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should return True' {
                    Test-TargetResource @ContextParams | Should Be $true
                }

            }

            Context 'AuditRuleInformation is specified, matching permissions exist' {

                $ContextParams = @{
                    Ensure = 'Absent'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AuditRuleInformation = @(

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'ReadAndExecute'
                                Inheritance = 'ThisFolderSubfoldersAndFiles'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'Modify'
                                Inheritance = 'ThisFolderOnly'
                                NoPropagateInherit = $false
                            }

                    )
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'ReadAndExecute',
                            @('ContainerInherit', 'ObjectInherit'),
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should return False' {
                    Test-TargetResource @ContextParams | Should Be $false
                }

            }

        }

        Describe "$Global:DSCResourceName\Test-TargetResource behavior with Ensure set to Present" {

            Context 'AuditRuleInformation is not specified, no permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

                It 'Should return False' {
                    Test-TargetResource @ContextParams | Should Be $false
                }

            }

            Context 'AuditRuleInformation is not specified, default permission exists, no other permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                $DefaultAuditRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $ContextParams.Principal,
                        'ReadAndExecute',
                        @('ContainerInherit', 'ObjectInherit'),
                        'None',
                        'Failure'
                    )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $DefaultAuditRule

                It 'Should return True' {
                    Test-TargetResource @ContextParams | Should Be $true
                }

            }

            Context 'AuditRuleInformation is not specified, default permission exists, other permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                $DefaultAuditRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $ContextParams.Principal,
                        'ReadAndExecute',
                        @('ContainerInherit', 'ObjectInherit'),
                        'None',
                        'Failure'
                    )

                $TempAuditRules = @(

                    $DefaultAuditRule

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should return False' {
                    Test-TargetResource @ContextParams | Should Be $false
                }

            }

            Context 'AuditRuleInformation is not specified, no default permission exists, other permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should return False' {
                    Test-TargetResource @ContextParams | Should Be $false
                }

            }

            Context 'AuditRuleInformation is specified, no permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AuditRuleInformation = @(

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'ReadAndExecute'
                                Inheritance = 'ThisFolderSubfoldersAndFiles'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'Modify'
                                Inheritance = 'ThisFolderOnly'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'CreateFiles', 'AppendData'
                                Inheritance = 'SubfoldersAndFilesOnly'
                                NoPropagateInherit = $false
                            }

                    )
                }

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

                It 'Should return False' {
                    Test-TargetResource @ContextParams | Should Be $false
                }

            }

            Context 'AuditRuleInformation is specified, desired permissions exist, other permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AuditRuleInformation = @(

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'ReadAndExecute'
                                Inheritance = 'ThisFolderSubfoldersAndFiles'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'Modify'
                                Inheritance = 'ThisFolderOnly'
                                NoPropagateInherit = $false
                            }

                    )
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'ReadAndExecute',
                            @('ContainerInherit', 'ObjectInherit'),
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should return False' {
                    Test-TargetResource @ContextParams | Should Be $false
                }

            }

            Context 'AuditRuleInformation is specified, permissions exist and match the desired state' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AuditRuleInformation = @(

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'ReadAndExecute'
                                Inheritance = 'ThisFolderSubfoldersAndFiles'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'Modify'
                                Inheritance = 'ThisFolderOnly'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'CreateFiles', 'AppendData'
                                Inheritance = 'SubfoldersAndFilesOnly'
                                NoPropagateInherit = $false
                            }

                    )
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'ReadAndExecute',
                            @('ContainerInherit', 'ObjectInherit'),
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should return True' {
                    Test-TargetResource @ContextParams | Should Be $true
                }

            }

        }

        Describe "$Global:DSCResourceName\Set-TargetResource behavior with Ensure set to Absent" {

            Context 'AuditRuleInformation is not specified, permissions exist' {

                $ContextParams = @{
                    Ensure = 'Absent'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'ReadAndExecute',
                            @('ContainerInherit', 'ObjectInherit'),
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should remove all permissions' {

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be $TempAuditRules.Count

                    Test-TargetResource @ContextParams | Should Be $false

                    Set-TargetResource @ContextParams

                    Test-TargetResource @ContextParams | Should Be $true

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be 0

                }

            }

            Context 'AuditRuleInformation is specified, matching permissions exist' {

                $ContextParams = @{
                    Ensure = 'Absent'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AuditRuleInformation = @(

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'ReadAndExecute'
                                Inheritance = 'ThisFolderSubfoldersAndFiles'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'Modify'
                                Inheritance = 'ThisFolderOnly'
                                NoPropagateInherit = $false
                            }

                    )
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'ReadAndExecute',
                            @('ContainerInherit', 'ObjectInherit'),
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should remove matching permissions' {

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be $TempAuditRules.Count

                    Test-TargetResource @ContextParams | Should Be $false

                    Set-TargetResource @ContextParams

                    Test-TargetResource @ContextParams | Should Be $true

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be ($TempAuditRules.Count - $ContextParams.AuditRuleInformation.Count)

                }

            }

        }

        Describe "$Global:DSCResourceName\Set-TargetResource behavior with Ensure set to Present" {

            Context 'AuditRuleInformation is not specified, no permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                $DefaultAuditRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $ContextParams.Principal,
                        'ReadAndExecute',
                        @('ContainerInherit', 'ObjectInherit'),
                        'None',
                        'Failure'
                    )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

                It 'Should add the default permission' {

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be 0

                    Test-TargetResource @ContextParams | Should Be $false

                    Set-TargetResource @ContextParams

                    Test-TargetResource @ContextParams | Should Be $true

                    $AccessRules = @(
                        (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                            {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                        )
                    )

                    $AccessRules.Count | Should Be 1
                    $AccessRules[0].FileSystemRights | Should Be $DefaultAuditRule.FileSystemRights
                    $AccessRules[0].AuditFlags | Should Be $DefaultAuditRule.AuditFlags
                    $AccessRules[0].InheritanceFlags | Should Be $DefaultAuditRule.InheritanceFlags
                    $AccessRules[0].PropagationFlags | Should Be $DefaultAuditRule.PropagationFlags
                }

            }

            Context 'AuditRuleInformation is not specified, default permission exists, other permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                $DefaultAuditRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $ContextParams.Principal,
                        'ReadAndExecute',
                        @('ContainerInherit', 'ObjectInherit'),
                        'None',
                        'Failure'
                    )

                $TempAuditRules = @(

                    $DefaultAuditRule

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should remove other permissions' {

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be $TempAuditRules.Count

                    Test-TargetResource @ContextParams | Should Be $false

                    Set-TargetResource @ContextParams

                    Test-TargetResource @ContextParams | Should Be $true

                    $AccessRules = @(
                        (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                            {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                        )
                    )

                    $AccessRules.Count | Should Be 1
                    $AccessRules[0].FileSystemRights | Should Be $DefaultAuditRule.FileSystemRights
                    $AccessRules[0].AuditFlags | Should Be $DefaultAuditRule.AuditFlags
                    $AccessRules[0].InheritanceFlags | Should Be $DefaultAuditRule.InheritanceFlags
                    $AccessRules[0].PropagationFlags | Should Be $DefaultAuditRule.PropagationFlags

                }

            }

            Context 'AuditRuleInformation is not specified, no default permission exists, other permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                }

                $DefaultAuditRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $ContextParams.Principal,
                        'ReadAndExecute',
                        @('ContainerInherit', 'ObjectInherit'),
                        'None',
                        'Failure'
                    )

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should add the default permission and remove other permissions' {

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be $TempAuditRules.Count

                    Test-TargetResource @ContextParams | Should Be $false

                    Set-TargetResource @ContextParams

                    Test-TargetResource @ContextParams | Should Be $true

                    $AccessRules = @(
                        (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                            {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                        )
                    )

                    $AccessRules.Count | Should Be 1
                    $AccessRules[0].FileSystemRights | Should Be $DefaultAuditRule.FileSystemRights
                    $AccessRules[0].AuditFlags | Should Be $DefaultAuditRule.AuditFlags
                    $AccessRules[0].InheritanceFlags | Should Be $DefaultAuditRule.InheritanceFlags
                    $AccessRules[0].PropagationFlags | Should Be $DefaultAuditRule.PropagationFlags

                }

            }

            Context 'AuditRuleInformation is specified, no permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AuditRuleInformation = @(

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'ReadAndExecute'
                                Inheritance = 'ThisFolderSubfoldersAndFiles'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'Modify'
                                Inheritance = 'ThisFolderOnly'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'CreateFiles', 'AppendData'
                                Inheritance = 'SubfoldersAndFilesOnly'
                                NoPropagateInherit = $false
                            }

                    )
                }

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

                It 'Should add the desired permissions' {

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be 0

                    Test-TargetResource @ContextParams | Should Be $false

                    Set-TargetResource @ContextParams

                    Test-TargetResource @ContextParams | Should Be $true

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be $ContextParams.AuditRuleInformation.Count

                }

            }

            Context 'AuditRuleInformation is specified, desired permissions exist, other permissions exist' {

                $ContextParams = @{
                    Ensure = 'Present'
                    Path = 'TestDrive:\' + [System.IO.Path]::GetRandomFileName()
                    Principal = 'BUILTIN\Users'
                    AuditRuleInformation = @(

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'ReadAndExecute'
                                Inheritance = 'ThisFolderSubfoldersAndFiles'
                                NoPropagateInherit = $false
                            }

                        New-CimInstance -ClientOnly `
                            -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                            -ClassName cNtfsAuditRuleInformation `
                            -Property @{
                                AuditFlags = 'Failure'
                                FileSystemRights = 'Modify'
                                Inheritance = 'ThisFolderOnly'
                                NoPropagateInherit = $false
                            }

                    )
                }

                $TempAuditRules = @(

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'ReadAndExecute',
                            @('ContainerInherit', 'ObjectInherit'),
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            'Modify',
                            'None',
                            'None',
                            'Failure'
                        )

                    New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                        -ArgumentList @(
                            $ContextParams.Principal,
                            @('CreateFiles', 'AppendData'),
                            @('ContainerInherit', 'ObjectInherit'),
                            'InheritOnly',
                            'Failure'
                        )

                )

                Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AuditRulesToAdd $TempAuditRules

                It 'Should remove other permissions' {

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be $TempAuditRules.Count

                    Test-TargetResource @ContextParams | Should Be $false

                    Set-TargetResource @ContextParams

                    Test-TargetResource @ContextParams | Should Be $true

                    (Get-Acl -Path $ContextParams.Path -Audit).Audit.Where(
                        {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.Principal}
                    ).Count |
                    Should Be $ContextParams.AuditRuleInformation.Count

                }

            }

        }

        Describe "$Global:DSCResourceName\ConvertFrom-FileSystemAuditRule" {

            $DescribeParams = @{
                Principal = 'BUILTIN\Users'
                AuditFlags = 'Failure'
                FileSystemRights = @('ReadAndExecute', 'Write', 'Synchronize')
            }

            Context 'PropagationFlags has the NoPropagateInherit flag set' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $DescribeParams.Principal,
                        $DescribeParams.FileSystemRights,
                        @('ContainerInherit', 'ObjectInherit'),
                        'NoPropagateInherit',
                        $DescribeParams.AuditFlags
                    )

                It 'Should return NoPropagateInherit set to True' {
                    $Result = ConvertFrom-FileSystemAuditRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance | Should Be 'ThisFolderSubfoldersAndFiles'
                    $Result.NoPropagateInherit | Should Be $true
                }

            }

            Context 'InheritanceFlags is None and PropagationFlags is None' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $DescribeParams.Principal,
                        $DescribeParams.FileSystemRights,
                        'None',
                        'None',
                        $DescribeParams.AuditFlags
                    )

                It 'Should return Inheritance set to ThisFolderOnly if ItemType is Directory' {
                    $Result = ConvertFrom-FileSystemAuditRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance | Should Be 'ThisFolderOnly'
                    $Result.NoPropagateInherit | Should Be $false
                }

                It 'Should return Inheritance set to None if ItemType is File' {
                    $Result = ConvertFrom-FileSystemAuditRule -ItemType File -InputObject $AccessRule
                    $Result.Inheritance | Should Be 'None'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is "ContainerInherit, ObjectInherit" and PropagationFlags is None' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $DescribeParams.Principal,
                        $DescribeParams.FileSystemRights,
                        @('ContainerInherit', 'ObjectInherit'),
                        'None',
                        $DescribeParams.AuditFlags
                    )

                It 'Should return Inheritance set to ThisFolderSubfoldersAndFiles' {
                    $Result = ConvertFrom-FileSystemAuditRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance | Should Be 'ThisFolderSubfoldersAndFiles'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is ContainerInherit and PropagationFlags is None' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $DescribeParams.Principal,
                        $DescribeParams.FileSystemRights,
                        'ContainerInherit',
                        'None',
                        $DescribeParams.AuditFlags
                    )

                It 'Should return Inheritance set to ThisFolderAndSubfolders' {
                    $Result = ConvertFrom-FileSystemAuditRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance | Should Be 'ThisFolderAndSubfolders'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is ObjectInherit and PropagationFlags is None' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $DescribeParams.Principal,
                        $DescribeParams.FileSystemRights,
                        'ObjectInherit',
                        'None',
                        $DescribeParams.AuditFlags
                    )

                It 'Should return Inheritance set to ThisFolderAndFiles' {
                    $Result = ConvertFrom-FileSystemAuditRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance | Should Be 'ThisFolderAndFiles'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is "ContainerInherit, ObjectInherit" and PropagationFlags is InheritOnly' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $DescribeParams.Principal,
                        $DescribeParams.FileSystemRights,
                        @('ContainerInherit', 'ObjectInherit'),
                        'InheritOnly',
                        $DescribeParams.AuditFlags
                    )

                It 'Should return Inheritance set to SubfoldersAndFilesOnly' {
                    $Result = ConvertFrom-FileSystemAuditRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance | Should Be 'SubfoldersAndFilesOnly'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is ContainerInherit and PropagationFlags is InheritOnly' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $DescribeParams.Principal,
                        $DescribeParams.FileSystemRights,
                        'ContainerInherit',
                        'InheritOnly',
                        $DescribeParams.AuditFlags
                    )

                It 'Should return Inheritance set to SubfoldersOnly' {
                    $Result = ConvertFrom-FileSystemAuditRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance | Should Be 'SubfoldersOnly'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

            Context 'InheritanceFlags is ObjectInherit and PropagationFlags is InheritOnly' {

                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule `
                    -ArgumentList @(
                        $DescribeParams.Principal,
                        $DescribeParams.FileSystemRights,
                        'ObjectInherit',
                        'InheritOnly',
                        $DescribeParams.AuditFlags
                    )

                It 'Should return Inheritance set to FilesOnly' {
                    $Result = ConvertFrom-FileSystemAuditRule -ItemType Directory -InputObject $AccessRule
                    $Result.Inheritance | Should Be 'FilesOnly'
                    $Result.NoPropagateInherit | Should Be $false
                }

            }

        }

        Describe "$Global:DSCResourceName\New-FileSystemAuditRule" {

            $DescribeParams = @{
                Principal = 'BUILTIN\Users'
                AuditFlags = 'Failure'
                FileSystemRights = @('ReadAndExecute', 'Write')
            }

            Context 'ItemType is Directory and NoPropagateInherit is False' {

                $ContextParams = $DescribeParams.Clone()
                $ContextParams.Add('ItemType', 'Directory')
                $ContextParams.Add('NoPropagateInherit', $false)

                It 'Inheritance is Null' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance $null
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is None' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance None
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderOnly' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance ThisFolderOnly
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderSubfoldersAndFiles' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance ThisFolderSubfoldersAndFiles
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderAndSubfolders' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance ThisFolderAndSubfolders
                    $Result.InheritanceFlags | Should Be 'ContainerInherit'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderAndFiles' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance ThisFolderAndFiles
                    $Result.InheritanceFlags | Should Be 'ObjectInherit'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is SubfoldersAndFilesOnly' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance SubfoldersAndFilesOnly
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'InheritOnly'
                }

                It 'Inheritance is SubfoldersOnly' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance SubfoldersOnly
                    $Result.InheritanceFlags | Should Be 'ContainerInherit'
                    $Result.PropagationFlags | Should Be 'InheritOnly'
                }

                It 'Inheritance is FilesOnly' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance FilesOnly
                    $Result.InheritanceFlags | Should Be 'ObjectInherit'
                    $Result.PropagationFlags | Should Be 'InheritOnly'
                }

            }

            Context 'ItemType is Directory and NoPropagateInherit is True' {

                $ContextParams = $DescribeParams.Clone()
                $ContextParams.Add('ItemType', 'Directory')
                $ContextParams.Add('NoPropagateInherit', $true)

                It 'Inheritance is Null' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance $null
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is None' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance None
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderOnly' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance ThisFolderOnly
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
                }

                It 'Inheritance is ThisFolderSubfoldersAndFiles' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance ThisFolderSubfoldersAndFiles
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is ThisFolderAndSubfolders' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance ThisFolderAndSubfolders
                    $Result.InheritanceFlags | Should Be 'ContainerInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is ThisFolderAndFiles' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance ThisFolderAndFiles
                    $Result.InheritanceFlags | Should Be 'ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is SubfoldersAndFilesOnly' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance SubfoldersAndFilesOnly
                    $Result.InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is SubfoldersOnly' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance SubfoldersOnly
                    $Result.InheritanceFlags | Should Be 'ContainerInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

                It 'Inheritance is FilesOnly' {
                    $Result = New-FileSystemAuditRule @ContextParams -Inheritance FilesOnly
                    $Result.InheritanceFlags | Should Be 'ObjectInherit'
                    $Result.PropagationFlags | Should Be 'NoPropagateInherit'
                }

            }

            Context 'ItemType is File' {

                It 'Should ignore Inheritance and NoPropagateInherit' {
                    $Result = New-FileSystemAuditRule @DescribeParams -ItemType File `
                        -Inheritance ThisFolderSubfoldersAndFiles -NoPropagateInherit $true
                    $Result.InheritanceFlags | Should Be 'None'
                    $Result.PropagationFlags | Should Be 'None'
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

        Describe "$Global:DSCResourceName\Resolve-IdentityReference" {

            It 'Should resolve by SID' {
                $Result = Resolve-IdentityReference -Identity 'S-1-5-32-545'
                $Result.Name | Should Be 'BUILTIN\Users'
                $Result.SID | Should Be 'S-1-5-32-545'
            }

            It 'Should resolve by Name' {
                $Result = Resolve-IdentityReference -Identity 'Users'
                $Result.Name | Should Be 'BUILTIN\Users'
                $Result.SID | Should Be 'S-1-5-32-545'
            }

            It 'Should throw if Identity is invalid' {
                {Resolve-IdentityReference -Identity $null} | Should Throw
            }

            It 'Should write a non-terminating error if Identity cannot be resolved' {
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
