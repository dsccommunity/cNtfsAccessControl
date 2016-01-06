$DSCModuleName   = 'cNtfsAccessControl'
$DSCResourceName = 'cNtfsPermissionsInheritance'

$JoinPathSplat = @{
    Path = $PSScriptRoot
    ChildPath = "..\..\DSCResources\$DSCResourceName\$DSCResourceName.psm1"
    Resolve = $true
    ErrorAction = 'Stop'
}
$DSCResourceModuleFile = Get-Item -Path (Join-Path @JoinPathSplat)

if ($env:APPVEYOR_BUILD_VERSION)
{
    Add-WindowsFeature -Name Web-Server -Verbose
}

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

    Describe "$DSCResourceName\Get-TargetResource" {

    }

    Describe "$DSCResourceName\Test-TargetResource" {

    } 

    Describe "$DSCResourceName\Set-TargetResource" {

    } 

}

