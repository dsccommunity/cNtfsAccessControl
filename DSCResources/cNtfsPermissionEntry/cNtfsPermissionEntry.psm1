#requires -Version 4.0 -Modules CimCmdlets

Set-StrictMode -Version Latest

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Absent', 'Present')]
        [String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Directory', 'File')]
        [String]
        $ItemType,

        [Parameter(Mandatory = $true)]
        [String]
        $Principal,

        [Parameter(Mandatory = $false)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlInformation
    )

    $PSBoundParameters.GetEnumerator() |
    ForEach-Object -Begin {
        $Width = $PSBoundParameters.Keys.Length | Sort-Object -Descending | Select-Object -First 1
    } -Process {
        "{0,-$($Width)} : '{1}'" -f $_.Key, ($_.Value -join ', ') |
        Write-Verbose
    }

    if ($PSBoundParameters.ContainsKey('ItemType'))
    {
        Write-Verbose -Message 'The ItemType property is deprecated and should not be used.'
    }

    $Acl = Get-Acl -Path $Path -ErrorAction Stop

    if ($Acl -is [System.Security.AccessControl.DirectorySecurity])
    {
        $ItemType = 'Directory'
    }
    else
    {
        $ItemType = 'File'
    }

    $Identity = Resolve-IdentityReference -Identity $Principal -ErrorAction Stop

    [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules = @(
        $Acl.Access |
        Where-Object -FilterScript {
            ($_.IsInherited -eq $false) -and
            ($_.IdentityReference -eq $Identity.Name)
        }
    )

    Write-Verbose -Message "Current Permission Entry Count : $($AccessRules.Count)"

    $CimAccessRules = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    if ($AccessRules.Count -ne 0)
    {
        $AccessRules |
        ConvertFrom-FileSystemAccessRule -ItemType $ItemType |
        ForEach-Object -Process {

            $CimAccessRule = New-CimInstance -ClientOnly `
                -Namespace 'root/Microsoft/Windows/DesiredStateConfiguration' `
                -ClassName 'cNtfsAccessControlInformation' `
                -Property @{
                    AccessControlType = $_.AccessControlType
                    FileSystemRights = $_.FileSystemRights
                    Inheritance = $_.Inheritance
                    NoPropagateInherit = $_.NoPropagateInherit
                }

            $CimAccessRules.Add($CimAccessRule)

        }
    }

    if ($Ensure -eq 'Absent')
    {
        if ($AccessRules.Count -eq 0)
        {
            $EnsureResult = 'Absent'
        }
        else
        {
            $EnsureResult = 'Present'
        }
    }
    else
    {
        $EnsureResult = 'Present'

        [PSCustomObject[]]$PermissionEntries = @()

        if ($PSBoundParameters.ContainsKey('AccessControlInformation'))
        {
            foreach ($Item in $AccessControlInformation)
            {
                $AccessControlType = $Item.CimInstanceProperties.Where({$_.Name -eq 'AccessControlType'}).ForEach({$_.Value})
                $FileSystemRights = $Item.CimInstanceProperties.Where({$_.Name -eq 'FileSystemRights'}).ForEach({$_.Value})
                $Inheritance = $Item.CimInstanceProperties.Where({$_.Name -eq 'Inheritance'}).ForEach({$_.Value})
                $NoPropagateInherit = $Item.CimInstanceProperties.Where({$_.Name -eq 'NoPropagateInherit'}).ForEach({$_.Value})

                if (-not $AccessControlType)
                {
                    $AccessControlType = 'Allow'
                }

                if (-not $FileSystemRights)
                {
                    $FileSystemRights = 'ReadAndExecute'
                }

                if (-not $NoPropagateInherit)
                {
                    $NoPropagateInherit = $false
                }

                $PermissionEntries += [PSCustomObject]@{
                    AccessControlType = $AccessControlType
                    FileSystemRights = $FileSystemRights
                    Inheritance = $Inheritance
                    NoPropagateInherit = $NoPropagateInherit
                }
            }
        }
        else
        {
            Write-Verbose -Message 'The AccessControlInformation property is not specified. The default permission entry will be used as the reference entry.'

            $PermissionEntries += [PSCustomObject]@{
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = $null
                NoPropagateInherit = $false
            }
        }

        Write-Verbose -Message "Desired Permission Entry Count : $($PermissionEntries.Count)"

        foreach ($Item in $PermissionEntries)
        {
            $ReferenceRule = ConvertTo-FileSystemAccessRule `
                -ItemType $ItemType `
                -Principal $Identity.Name `
                -AccessControlType $Item.AccessControlType `
                -FileSystemRights $Item.FileSystemRights `
                -Inheritance $Item.Inheritance `
                -NoPropagateInherit $Item.NoPropagateInherit `
                -ErrorAction Stop

            $MatchingRule = $AccessRules |
                Where-Object -FilterScript {
                    ($_.AccessControlType -eq $ReferenceRule.AccessControlType) -and
                    ($_.FileSystemRights -eq $ReferenceRule.FileSystemRights) -and
                    ($_.InheritanceFlags -eq $ReferenceRule.InheritanceFlags) -and
                    ($_.PropagationFlags -eq $ReferenceRule.PropagationFlags)
                }

            if ($MatchingRule)
            {
                "(FOUND) Permission Entry:",
                "> IdentityReference : '$($MatchingRule.IdentityReference)'",
                "> AccessControlType : '$($MatchingRule.AccessControlType)'",
                "> FileSystemRights  : '$($MatchingRule.FileSystemRights)'",
                "> InheritanceFlags  : '$($MatchingRule.InheritanceFlags)'",
                "> PropagationFlags  : '$($MatchingRule.PropagationFlags)'" |
                Write-Verbose
            }
            else
            {
                $EnsureResult = 'Absent'

                "(NOT FOUND) Permission Entry:",
                "> IdentityReference : '$($ReferenceRule.IdentityReference)'",
                "> AccessControlType : '$($ReferenceRule.AccessControlType)'",
                "> FileSystemRights  : '$($ReferenceRule.FileSystemRights)'",
                "> InheritanceFlags  : '$($ReferenceRule.InheritanceFlags)'",
                "> PropagationFlags  : '$($ReferenceRule.PropagationFlags)'" |
                Write-Verbose
            }
        }
    }

    $ReturnValue = @{
        Ensure = $EnsureResult
        Path = $Path
        ItemType = $ItemType
        Principal = $Principal
        AccessControlInformation = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessRules)
    }

    return $ReturnValue
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Absent', 'Present')]
        [String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Directory', 'File')]
        [String]
        $ItemType,

        [Parameter(Mandatory = $true)]
        [String]
        $Principal,

        [Parameter(Mandatory = $false)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlInformation
    )

    $TargetResource = Get-TargetResource @PSBoundParameters

    $InDesiredState = $Ensure -eq $TargetResource.Ensure

    if ($InDesiredState -eq $true)
    {
        Write-Verbose -Message 'The target resource is already in the desired state. No action is required.'
    }
    else
    {
        Write-Verbose -Message 'The target resource is not in the desired state.'
    }

    return $InDesiredState
}

function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Absent', 'Present')]
        [String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Directory', 'File')]
        [String]
        $ItemType,

        [Parameter(Mandatory = $true)]
        [String]
        $Principal,

        [Parameter(Mandatory = $false)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlInformation
    )

    if ($PSBoundParameters.ContainsKey('ItemType'))
    {
        Write-Verbose -Message 'The ItemType property is deprecated and should not be used.'
    }

    $Acl = Get-Acl -Path $Path -ErrorAction Stop

    if ($Acl -is [System.Security.AccessControl.DirectorySecurity])
    {
        $ItemType = 'Directory'
    }
    else
    {
        $ItemType = 'File'
    }

    $Identity = Resolve-IdentityReference -Identity $Principal -ErrorAction Stop

    [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules = @(
        $Acl.Access |
        Where-Object -FilterScript {
            ($_.IsInherited -eq $false) -and
            ($_.IdentityReference -eq $Identity.Name)
        }
    )

    if ($AccessRules.Count -ne 0)
    {
        "Removing all explicit permissions for principal '{0}' on path '{1}'." -f $($AccessRules[0].IdentityReference), $Path |
        Write-Verbose

        $Modified = $null
        $Acl.ModifyAccessRule('RemoveAll', $AccessRules[0], [Ref]$Modified)
    }

    if ($Ensure -eq 'Present')
    {
        [PSCustomObject[]]$PermissionEntries = @()

        if ($PSBoundParameters.ContainsKey('AccessControlInformation'))
        {
            foreach ($Item in $AccessControlInformation)
            {
                $AccessControlType = $Item.CimInstanceProperties.Where({$_.Name -eq 'AccessControlType'}).ForEach({$_.Value})
                $FileSystemRights = $Item.CimInstanceProperties.Where({$_.Name -eq 'FileSystemRights'}).ForEach({$_.Value})
                $Inheritance = $Item.CimInstanceProperties.Where({$_.Name -eq 'Inheritance'}).ForEach({$_.Value})
                $NoPropagateInherit = $Item.CimInstanceProperties.Where({$_.Name -eq 'NoPropagateInherit'}).ForEach({$_.Value})

                if (-not $AccessControlType)
                {
                    $AccessControlType = 'Allow'
                }

                if (-not $FileSystemRights)
                {
                    $FileSystemRights = 'ReadAndExecute'
                }

                if (-not $NoPropagateInherit)
                {
                    $NoPropagateInherit = $false
                }

                $PermissionEntries += [PSCustomObject]@{
                    AccessControlType = $AccessControlType
                    FileSystemRights = $FileSystemRights
                    Inheritance = $Inheritance
                    NoPropagateInherit = $NoPropagateInherit
                }
            }
        }
        else
        {
            $PermissionEntries += [PSCustomObject]@{
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = $null
                NoPropagateInherit = $false
            }
        }

        foreach ($Item in $PermissionEntries)
        {
            $ReferenceRule = ConvertTo-FileSystemAccessRule `
                -ItemType $ItemType `
                -Principal $Identity.Name `
                -AccessControlType $Item.AccessControlType `
                -FileSystemRights $Item.FileSystemRights `
                -Inheritance $Item.Inheritance `
                -NoPropagateInherit $Item.NoPropagateInherit `
                -ErrorAction Stop

            "Adding permission entry for principal '{0}' on path '{1}'." -f $Identity.Name, $Path |
            Write-Verbose

            $Acl.AddAccessRule($ReferenceRule)
        }
    }

    Set-FileSystemAccessControl -Path $Path -AclObject $Acl
}

#region Helper Functions

function ConvertFrom-FileSystemAccessRule
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Directory', 'File')]
        [String]
        $ItemType,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.AccessControl.FileSystemAccessRule]
        $InputObject
    )
    process
    {
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = $InputObject.InheritanceFlags
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags = $InputObject.PropagationFlags

        $NoPropagateInherit = $PropagationFlags.HasFlag([System.Security.AccessControl.PropagationFlags]::NoPropagateInherit)

        if ($NoPropagateInherit)
        {
            [System.Security.AccessControl.PropagationFlags]$PropagationFlags = $PropagationFlags -bxor [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
        }

        if ($InheritanceFlags -eq 'None' -and $PropagationFlags -eq 'None')
        {
            if ($ItemType -eq 'Directory')
            {
                $Inheritance = 'ThisFolderOnly'
            }
            else
            {
                $Inheritance = 'None'
            }
        }
        elseif ($InheritanceFlags -eq 'ContainerInherit, ObjectInherit' -and $PropagationFlags -eq 'None')
        {
            $Inheritance = 'ThisFolderSubfoldersAndFiles'
        }
        elseif ($InheritanceFlags -eq 'ContainerInherit' -and $PropagationFlags -eq 'None')
        {
            $Inheritance = 'ThisFolderAndSubfolders'
        }
        elseif ($InheritanceFlags -eq 'ObjectInherit' -and $PropagationFlags -eq 'None')
        {
            $Inheritance = 'ThisFolderAndFiles'
        }
        elseif ($InheritanceFlags -eq 'ContainerInherit, ObjectInherit' -and $PropagationFlags -eq 'InheritOnly')
        {
            $Inheritance = 'SubfoldersAndFilesOnly'
        }
        elseif ($InheritanceFlags -eq 'ContainerInherit' -and $PropagationFlags -eq 'InheritOnly')
        {
            $Inheritance = 'SubfoldersOnly'
        }
        elseif ($InheritanceFlags -eq 'ObjectInherit' -and $PropagationFlags -eq 'InheritOnly')
        {
            $Inheritance = 'FilesOnly'
        }

        $OutputObject = [PSCustomObject]@{
            ItemType = $ItemType
            Principal = [String]$InputObject.IdentityReference
            AccessControlType = [String]$InputObject.AccessControlType
            FileSystemRights = [String]$InputObject.FileSystemRights
            Inheritance = $Inheritance
            NoPropagateInherit = $NoPropagateInherit
        }

        return $OutputObject
    }
}

function ConvertTo-FileSystemAccessRule
{
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.FileSystemAccessRule])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('Directory', 'File')]
        [String]
        $ItemType,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]
        $Principal,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('Allow', 'Deny')]
        [String]
        $AccessControlType,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.Security.AccessControl.FileSystemRights]
        $FileSystemRights,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(
            $null,
            'None',
            'ThisFolderOnly',
            'ThisFolderSubfoldersAndFiles',
            'ThisFolderAndSubfolders',
            'ThisFolderAndFiles',
            'SubfoldersAndFilesOnly',
            'SubfoldersOnly',
            'FilesOnly'
        )]
        [String]
        $Inheritance = 'ThisFolderSubfoldersAndFiles',

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Boolean]
        $NoPropagateInherit = $false
    )
    process
    {
        if ($ItemType -eq 'Directory')
        {
            switch ($Inheritance)
            {
                {$_ -in @('None', 'ThisFolderOnly')}
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'None'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }

                'ThisFolderSubfoldersAndFiles'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit', 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }

                'ThisFolderAndSubfolders'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }

                'ThisFolderAndFiles'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }

                'SubfoldersAndFilesOnly'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit', 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'InheritOnly'
                }

                'SubfoldersOnly'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'InheritOnly'
                }

                'FilesOnly'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'InheritOnly'
                }

                default
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit', 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }
            }

            if ($NoPropagateInherit -eq $true -and $InheritanceFlags -ne 'None')
            {
                [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'NoPropagateInherit'
            }
        }
        else
        {
            [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'None'
            [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
        }

        $OutputObject = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $Principal, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType
        )

        return $OutputObject
    }
}

function Set-FileSystemAccessControl
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.AccessControl.FileSystemSecurity]
        $AclObject
    )

    $PathInfo = Resolve-Path -Path $Path -ErrorAction Stop

    if ($PSCmdlet.ShouldProcess($Path))
    {
        if ($AclObject -is [System.Security.AccessControl.DirectorySecurity])
        {
            [System.IO.Directory]::SetAccessControl($PathInfo.ProviderPath, $AclObject)
        }
        else
        {
            [System.IO.File]::SetAccessControl($PathInfo.ProviderPath, $AclObject)
        }
    }
}

function Resolve-IdentityReference
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Identity
    )
    process
    {
        try
        {
            Write-Verbose -Message "Resolving identity reference '$Identity'."

            if ($Identity -match '^S-\d-(\d+-){1,14}\d+$')
            {
                [System.Security.Principal.SecurityIdentifier]$Identity = $Identity
            }
            else
            {
                [System.Security.Principal.NTAccount]$Identity = $Identity
            }

            $SID = $Identity.Translate([System.Security.Principal.SecurityIdentifier])
            $NTAccount = $SID.Translate([System.Security.Principal.NTAccount])

            $OutputObject = [PSCustomObject]@{
                Name = $NTAccount.Value
                SID = $SID.Value
            }

            return $OutputObject
        }
        catch
        {
            $ErrorMessage = "Could not resolve identity reference '{0}': '{1}'." -f $Identity, $_.Exception.Message
            Write-Error -Exception $_.Exception -Message $ErrorMessage
            return
        }
    }
}

#endregion
