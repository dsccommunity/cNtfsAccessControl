
#requires -Version 4.0 -Modules xDSCResourceDesigner

Split-Path -Path $PSScriptRoot -Parent |
Join-Path -ChildPath 'DSCResources' |
Get-ChildItem -Directory |
Test-xDscResource -Name {$_.FullName} -Verbose
