$Global:DSCModuleName   = 'cNtfsAccessControl'
$Global:DSCResourceName = 'cNtfsPermissionEntry'

$JoinPathSplat = @{
    Path = $PSScriptRoot
    ChildPath = "..\..\DSCResources\$DSCResourceName\$DSCResourceName.psm1"
    Resolve = $true
    ErrorAction = 'Stop'
}
$DSCResourceModuleFile = Get-Item -Path (Join-Path @JoinPathSplat)

if (Get-Module -Name $DSCResourceName)
{
    Remove-Module -Name $DSCResourceName
}

Import-Module -Name $DSCResourceModuleFile.FullName -Force

$ModuleRoot = "${env:ProgramFiles}\WindowsPowerShell\Modules\$DSCModuleName"

if (-not (Test-Path -Path $ModuleRoot -PathType Container))
{
    New-Item -Path $ModuleRoot -ItemType Directory | Out-Null
}

Copy-Item -Path "$PSScriptRoot\..\..\*" -Destination $ModuleRoot -Recurse -Force -Exclude '.git'

InModuleScope -ModuleName $DSCResourceName -ScriptBlock {

    Describe "how $DSCResourceName\Get-TargetResource responds" {}

    Describe "$DSCResourceName\ConvertFrom-FileSystemAccessRule" {

    }

    Describe "$DSCResourceName\ConvertTo-FileSystemAccessRule" {

    }

    Describe "$DSCResourceName\Resolve-IdentityReference" {

        Context 'SID is passed as input' {

            $Result = Resolve-IdentityReference -Identity 'S-1-5-32-544'

            It 'should resolve' {
                $Result.Name | Should Be 'BUILTIN\Administrators'
                $Result.SID  | Should Be 'S-1-5-32-544'
            }

        }

        It 'should resolve identity reference by Name' {
            $Result = Resolve-IdentityReference -Identity 'Event Log Readers'
            $Result.Name | Should Be 'BUILTIN\Event Log Readers'
            $Result.SID  | Should Be 'S-1-5-32-573'
        }

        It 'should write a non-terminating error if identity reference cannot be resolved' {
            {Resolve-IdentityReference -Identity 'CONTOSO\JDoe' -ErrorAction Stop} |
            Should Throw
        }

    }

}

