#requires -Version 4.0 -Modules CimCmdlets

Set-StrictMode -Version Latest

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [String]
        $Principal
    )

    $Acl = Get-Acl -Path $Path -ErrorAction Stop

    if ($Acl -is [System.Security.AccessControl.DirectorySecurity])
    {
        $ItemType = 'Directory'
    }
    else
    {
        $ItemType = 'File'
    }

    Write-Verbose "ItemType : $ItemType"

    $Identity = Resolve-IdentityReference -Identity $Principal -ErrorAction Stop

    [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules = @(
        $Acl.Access |
        Where-Object -FilterScript {
            ($_.IsInherited -eq $false) -and
            (($_.IdentityReference -eq $Identity.Name) -or ($_.IdentityReference -eq $Identity.SID))
        }
    )

    Write-Verbose -Message "Current permission entry count : $($AccessRules.Count)"

    $CimAccessRules = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    if ($AccessRules.Count -eq 0)
    {
        $EnsureResult = 'Absent'
    }
    else
    {
        $EnsureResult = 'Present'

        $AccessRules |
        ConvertFrom-FileSystemAccessRule -ItemType $ItemType |
        ForEach-Object -Process {

            $CimAccessRule = New-CimInstance -ClientOnly `
                -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                -ClassName cNtfsAccessControlInformation `
                -Property @{
                    AccessControlType = $_.AccessControlType
                    FileSystemRights = $_.FileSystemRights
                    Inheritance = $_.Inheritance
                    NoPropagateInherit = $_.NoPropagateInherit
                }

            $CimAccessRules.Add($CimAccessRule)

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

    $PSBoundParameters.GetEnumerator() |
    ForEach-Object -Begin {
        $Width = $PSBoundParameters.Keys.Length | Sort-Object | Select-Object -Last 1
    } -Process {
        "{0,-$($Width)} : '{1}'" -f $_.Key, ($_.Value -join ', ') |
        Write-Verbose
    }

    if ($PSBoundParameters.ContainsKey('ItemType'))
    {
        Write-Verbose -Message 'The ItemType property is deprecated and will be ignored.'
    }

    $InDesiredState = $true

    $Acl = Get-Acl -Path $Path -ErrorAction Stop

    if ($Acl -is [System.Security.AccessControl.DirectorySecurity])
    {
        $ItemType = 'Directory'
    }
    else
    {
        $ItemType = 'File'
    }

    Write-Verbose "ItemType : $ItemType"

    $Identity = Resolve-IdentityReference -Identity $Principal -ErrorAction Stop

    [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules = @(
        $Acl.Access |
        Where-Object -FilterScript {
            ($_.IsInherited -eq $false) -and
            (($_.IdentityReference -eq $Identity.Name) -or ($_.IdentityReference -eq $Identity.SID))
        }
    )

    Write-Verbose -Message "Current permission entry count : $($AccessRules.Count)"

    [PSCustomObject[]]$ReferenceRuleInfo = @()

    if ($PSBoundParameters.ContainsKey('AccessControlInformation'))
    {
        foreach ($Instance in $AccessControlInformation)
        {
            $AccessControlType = $Instance.CimInstanceProperties.Where({$_.Name -eq 'AccessControlType'}).ForEach({$_.Value})
            $FileSystemRights = $Instance.CimInstanceProperties.Where({$_.Name -eq 'FileSystemRights'}).ForEach({$_.Value})
            $Inheritance = $Instance.CimInstanceProperties.Where({$_.Name -eq 'Inheritance'}).ForEach({$_.Value})
            $NoPropagateInherit = [boolean]$Instance.CimInstanceProperties.Where({$_.Name -eq 'NoPropagateInherit'}).ForEach({$_.Value})

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

            $ReferenceRuleInfo += [PSCustomObject]@{
                AccessControlType = $AccessControlType
                FileSystemRights = $FileSystemRights
                Inheritance = $Inheritance
                NoPropagateInherit = $NoPropagateInherit
            }
        }
    }
    else
    {
        Write-Verbose -Message 'The AccessControlInformation property is not specified.'

        if ($Ensure -eq 'Present')
        {
            Write-Verbose -Message 'The default permission entry will be used as the reference permission entry.'

            $ReferenceRuleInfo += [PSCustomObject]@{
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = $null
                NoPropagateInherit = $false
            }
        }
    }

    if ($Ensure -eq 'Absent' -and $AccessRules.Count -ne 0)
    {
        if ($ReferenceRuleInfo.Count -ne 0)
        {
            $ReferenceRuleInfo |
            ForEach-Object -Begin {$Counter = 0} -Process {

                $Entry = $_

                $ReferenceRule = New-FileSystemAccessRule `
                    -ItemType $ItemType `
                    -Principal $Identity.Name `
                    -AccessControlType $Entry.AccessControlType `
                    -FileSystemRights $Entry.FileSystemRights `
                    -Inheritance $Entry.Inheritance `
                    -NoPropagateInherit $Entry.NoPropagateInherit `
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
                    ("Permission entry was found ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                    ("> IdentityReference : '{0}'" -f $MatchingRule.IdentityReference),
                    ("> AccessControlType : '{0}'" -f $MatchingRule.AccessControlType),
                    ("> FileSystemRights  : '{0}'" -f $MatchingRule.FileSystemRights),
                    ("> InheritanceFlags  : '{0}'" -f $MatchingRule.InheritanceFlags),
                    ("> PropagationFlags  : '{0}'" -f $MatchingRule.PropagationFlags) |
                    Write-Verbose

                    $InDesiredState = $false
                }
                else
                {
                    ("Permission entry was not found ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                    ("> IdentityReference : '{0}'" -f $ReferenceRule.IdentityReference),
                    ("> AccessControlType : '{0}'" -f $ReferenceRule.AccessControlType),
                    ("> FileSystemRights  : '{0}'" -f $ReferenceRule.FileSystemRights),
                    ("> InheritanceFlags  : '{0}'" -f $ReferenceRule.InheritanceFlags),
                    ("> PropagationFlags  : '{0}'" -f $ReferenceRule.PropagationFlags) |
                    Write-Verbose
                }

            }
        }
        else
        {
            # All explicit permissions associated with the specified principal should be removed.
            $InDesiredState = $false
        }
    }

    if ($Ensure -eq 'Present')
    {
        Write-Verbose -Message "Desired permission entry count : $($ReferenceRuleInfo.Count)"

        if ($AccessRules.Count -ne $ReferenceRuleInfo.Count)
        {
            Write-Verbose -Message 'The number of current permission entries is different from the number of desired permission entries.'

            $InDesiredState = $false
        }

        $ReferenceRuleInfo |
        ForEach-Object -Begin {$Counter = 0} -Process {

            $Entry = $_

            $ReferenceRule = New-FileSystemAccessRule `
                -ItemType $ItemType `
                -Principal $Identity.Name `
                -AccessControlType $Entry.AccessControlType `
                -FileSystemRights $Entry.FileSystemRights `
                -Inheritance $Entry.Inheritance `
                -NoPropagateInherit $Entry.NoPropagateInherit `
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
                ("Permission entry was found ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                ("> IdentityReference : '{0}'" -f $MatchingRule.IdentityReference),
                ("> AccessControlType : '{0}'" -f $MatchingRule.AccessControlType),
                ("> FileSystemRights  : '{0}'" -f $MatchingRule.FileSystemRights),
                ("> InheritanceFlags  : '{0}'" -f $MatchingRule.InheritanceFlags),
                ("> PropagationFlags  : '{0}'" -f $MatchingRule.PropagationFlags) |
                Write-Verbose
            }
            else
            {
                ("Permission entry was not found ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                ("> IdentityReference : '{0}'" -f $ReferenceRule.IdentityReference),
                ("> AccessControlType : '{0}'" -f $ReferenceRule.AccessControlType),
                ("> FileSystemRights  : '{0}'" -f $ReferenceRule.FileSystemRights),
                ("> InheritanceFlags  : '{0}'" -f $ReferenceRule.InheritanceFlags),
                ("> PropagationFlags  : '{0}'" -f $ReferenceRule.PropagationFlags) |
                Write-Verbose

                $InDesiredState = $false
            }

        }
    }

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

    $Acl = Get-Acl -Path $Path -ErrorAction Stop

    if ($Acl -is [System.Security.AccessControl.DirectorySecurity])
    {
        $ItemType = 'Directory'
    }
    else
    {
        $ItemType = 'File'
    }

    Write-Verbose "ItemType : $ItemType"

    $Identity = Resolve-IdentityReference -Identity $Principal -ErrorAction Stop

    [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules = @(
        $Acl.Access |
        Where-Object -FilterScript {
            ($_.IsInherited -eq $false) -and
            (($_.IdentityReference -eq $Identity.Name) -or ($_.IdentityReference -eq $Identity.SID))
        }
    )

    Write-Verbose -Message "Current permission entry count : $($AccessRules.Count)"

    [PSCustomObject[]]$ReferenceRuleInfo = @()

    if ($PSBoundParameters.ContainsKey('AccessControlInformation'))
    {
        foreach ($Instance in $AccessControlInformation)
        {
            $AccessControlType = $Instance.CimInstanceProperties.Where({$_.Name -eq 'AccessControlType'}).ForEach({$_.Value})
            $FileSystemRights = $Instance.CimInstanceProperties.Where({$_.Name -eq 'FileSystemRights'}).ForEach({$_.Value})
            $Inheritance = $Instance.CimInstanceProperties.Where({$_.Name -eq 'Inheritance'}).ForEach({$_.Value})
            $NoPropagateInherit = [boolean]$Instance.CimInstanceProperties.Where({$_.Name -eq 'NoPropagateInherit'}).ForEach({$_.Value})

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

            $ReferenceRuleInfo += [PSCustomObject]@{
                AccessControlType = $AccessControlType
                FileSystemRights = $FileSystemRights
                Inheritance = $Inheritance
                NoPropagateInherit = $NoPropagateInherit
            }
        }
    }
    else
    {
        Write-Verbose -Message 'The AccessControlInformation property is not specified.'

        if ($Ensure -eq 'Present')
        {
            Write-Verbose -Message 'The default permission entry will be added.'

            $ReferenceRuleInfo += [PSCustomObject]@{
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = $null
                NoPropagateInherit = $false
            }
        }
    }

    if ($Ensure -eq 'Absent' -and $AccessRules.Count -ne 0)
    {
        if ($ReferenceRuleInfo.Count -ne 0)
        {
            $ReferenceRuleInfo |
            ForEach-Object -Begin {$Counter = 0} -Process {

                $Entry = $_

                $ReferenceRule = New-FileSystemAccessRule `
                    -ItemType $ItemType `
                    -Principal $Identity.SID `
                    -AccessControlType $Entry.AccessControlType `
                    -FileSystemRights $Entry.FileSystemRights `
                    -Inheritance $Entry.Inheritance `
                    -NoPropagateInherit $Entry.NoPropagateInherit `
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
                    ("Removing permission entry ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                    ("> IdentityReference : '{0}'" -f $MatchingRule.IdentityReference),
                    ("> IdentityReference : '{0}'" -f $Identity.Name),
                    ("> AccessControlType : '{0}'" -f $MatchingRule.AccessControlType),
                    ("> FileSystemRights  : '{0}'" -f $MatchingRule.FileSystemRights),
                    ("> InheritanceFlags  : '{0}'" -f $MatchingRule.InheritanceFlags),
                    ("> PropagationFlags  : '{0}'" -f $MatchingRule.PropagationFlags) |
                    Write-Verbose

                    $Modified = $null
                    $Acl.ModifyAccessRule('RemoveSpecific', $MatchingRule, [ref]$Modified)
                    Write-Verbose "Modified : $($Modified|Out-String)"
                    if(!([bool]$Modified))
                    {
                        Write-Error -Exception "Removing permission entry failed"
                    }
                }
            }
        }
        else
        {
            "Removing all explicit permissions for principal '{0}'." -f $($AccessRules[0].IdentityReference) |
            Write-Verbose

            $MatchingRule = ConvertFrom-FileSystemAccessRule -ItemType $ItemType -InputObject $AccessRules[0] -ErrorAction Stop

            $ReferenceRule = New-FileSystemAccessRule `
                    -ItemType $ItemType `
                    -Principal $Identity.SID `
                    -AccessControlType $MatchingRule.AccessControlType `
                    -FileSystemRights $MatchingRule.FileSystemRights `
                    -Inheritance $MatchingRule.Inheritance `
                    -NoPropagateInherit $MatchingRule.NoPropagateInherit `
                    -ErrorAction Stop
            
            "Removing all explicit permissions for principal '{0}'." -f $($ReferenceRule.IdentityReference) |
            Write-Verbose

            $Modified = $null
            $Acl.ModifyAccessRule('RemoveAll', $ReferenceRule, [ref]$Modified)
            Write-Verbose "Modified : $($Modified|Out-String)"
            if(!([bool]$Modified))
            {
                Write-Error -Exception "Removing permission entry failed"
            }
        }
    }

    if ($Ensure -eq 'Present')
    {
        if ($AccessRules.Count -ne 0)
        {
            "Removing all explicit permissions for principal '{0}'." -f $($AccessRules[0].IdentityReference) |
            Write-Verbose

            $MatchingRule = ConvertFrom-FileSystemAccessRule -ItemType $ItemType -InputObject $AccessRules[0] -ErrorAction Stop

            $ReferenceRule = New-FileSystemAccessRule `
                    -ItemType $ItemType `
                    -Principal $Identity.SID `
                    -AccessControlType $MatchingRule.AccessControlType `
                    -FileSystemRights $MatchingRule.FileSystemRights `
                    -Inheritance $MatchingRule.Inheritance `
                    -NoPropagateInherit $MatchingRule.NoPropagateInherit `
                    -ErrorAction Stop

            "Removing all explicit permissions for principal '{0}'." -f $($ReferenceRule.IdentityReference) |
            Write-Verbose

            $Modified = $null
            $Acl.ModifyAccessRule('RemoveAll', $ReferenceRule, [ref]$Modified)
            Write-Verbose "Modified : $($Modified|Out-String)"
            if(!([bool]$Modified))
            {
                Write-Error -Exception "Removing permission entry failed"
            }
        }

        $ReferenceRuleInfo |
        ForEach-Object -Begin {$Counter = 0} -Process {

            $Entry = $_

            Write-Verbose "Filesystem rights before object creation : $($Entry.FileSystemRights)"

            $ReferenceRule = New-FileSystemAccessRule `
                    -ItemType $ItemType `
                    -Principal $Identity.SID `
                    -AccessControlType $Entry.AccessControlType `
                    -FileSystemRights $Entry.FileSystemRights `
                    -Inheritance $Entry.Inheritance `
                    -NoPropagateInherit $Entry.NoPropagateInherit `
                    -ErrorAction Stop

            ("Adding permission entry ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
            ("> IdentityReference : '{0}'" -f $ReferenceRule.IdentityReference),
            ("> IdentityReference : '{0}'" -f $Identity.Name),
            ("> AccessControlType : '{0}'" -f $ReferenceRule.AccessControlType),
            ("> FileSystemRights  : '{0}'" -f $ReferenceRule.FileSystemRights),
            ("> InheritanceFlags  : '{0}'" -f $ReferenceRule.InheritanceFlags),
            ("> PropagationFlags  : '{0}'" -f $ReferenceRule.PropagationFlags) |
            Write-Verbose

            $Acl.AddAccessRule($ReferenceRule)

        }
    }

    Set-FileSystemAccessControl -Path $Path -Acl $Acl
}

#region Helper Functions

function ConvertFrom-FileSystemAccessRule
{
    <#
    .SYNOPSIS
        Converts a FileSystemAccessRule object to a custom object.

    .DESCRIPTION
        The ConvertFrom-FileSystemAccessRule function converts a FileSystemAccessRule object to a custom object.

    .PARAMETER ItemType
        Specifies whether the item is a directory or a file.

    .PARAMETER InputObject
        Specifies the FileSystemAccessRule object to convert.
    #>
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
            [System.Security.AccessControl.PropagationFlags]$PropagationFlags =
                $PropagationFlags -bxor [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
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
         
        if([string]$($InputObject.FileSystemRights) -match "\d+")
        {
           "Found an integer permission $($InputObject.FileSystemRights)"|Write-Verbose
           $fileSystemRights = Convert-FileSystemRightsInteger -FileSystemRightsInteger ([System.Convert]::ToInt64( $($InputObject.FileSystemRights)))
        }
        else
        {
            $fileSystemRights = $($InputObject.FileSystemRights)
        }

        $OutputObject = [PSCustomObject]@{
            ItemType = $ItemType
            Principal = [String]$InputObject.IdentityReference
            AccessControlType = [String]$InputObject.AccessControlType
            FileSystemRights = [String]$fileSystemRights
            Inheritance = $Inheritance
            NoPropagateInherit = $NoPropagateInherit
        }

        return $OutputObject
    }
}

function New-FileSystemAccessRule
{
    <#
    .SYNOPSIS
        Creates a FileSystemAccessRule object.

    .DESCRIPTION
        The New-FileSystemAccessRule function creates a FileSystemAccessRule object
        that represents an abstraction of an access control entry (ACE).

    .PARAMETER ItemType
        Specifies whether the item is a directory or a file.

    .PARAMETER Principal
        Specifies the identity of the principal.

    .PARAMETER AccessControlType
        Specifies whether the ACE to be used to allow or deny access.

    .PARAMETER FileSystemRights
        Specifies the access rights to be granted to the principal.

    .PARAMETER Inheritance
        Specifies the inheritance type of the ACE.

    .PARAMETER NoPropagateInherit
        Specifies that the ACE is not propagated to child objects.
    #>
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


        if ($Principal -match '^S-\d-(\d+-){1,14}\d+$')
        {
            [System.Security.Principal.SecurityIdentifier]$IdentityRef = $Principal
        }
        else
        {
            [System.Security.Principal.NTAccount]$IdentityRef = $Principal
        }

        $OutputObject = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
            -ArgumentList $IdentityRef, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType

        return $OutputObject
    }
}

function Set-FileSystemAccessControl
{
    <#
    .SYNOPSIS
        Applies access control entries (ACEs) to the specified file or directory.

    .DESCRIPTION
        The Set-FileSystemAccessControl function applies access control entries (ACEs) to the specified file or directory.

    .PARAMETER Path
        Specifies the path to the file or directory.

    .PARAMETER Acl
        Specifies the access control list (ACL) object with the desired access control entries (ACEs)
        to apply to the file or directory described by the Path parameter.
    #>
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
        $Acl
    )

    $PathInfo = Resolve-Path -Path $Path -ErrorAction Stop

    if ($PSCmdlet.ShouldProcess($Path))
    {
        if ($Acl -is [System.Security.AccessControl.DirectorySecurity])
        {
            [System.IO.Directory]::SetAccessControl($PathInfo.ProviderPath, $Acl)
        }
        else
        {
            [System.IO.File]::SetAccessControl($PathInfo.ProviderPath, $Acl)
        }
    }
}

function Resolve-IdentityReference
{
    <#
    .SYNOPSIS
        Resolves the identity of the principal.

    .DESCRIPTION
        The Resolve-IdentityReference function resolves the identity of the principal
        and returns its down-level logon name and security identifier (SID).

    .PARAMETER Identity
        Specifies the identity of the principal.
    #>
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


#Author: Kent Yeabower
#https://gallery.technet.microsoft.com/scriptcenter/Convert-FileSystemRights-d1ee5f28
function Convert-FileSystemRightsInteger {
    [CmdletBinding()]
    Param
    (
        [int]$FileSystemRightsInteger = ""
    )

    try
    {

    $FileSystemRights = $FileSystemRightsInteger

    write-verbose "Current FileSystemRights is integer value: $FileSystemRights"
    #####################################################
    #region   Create FileSystemRight Enumeration Hash Table   #
    #####################################################

    #FYI, if we wanted to just see the values, we can run the below code:
    ##[System.Enum]::GetValues([System.Security.AccessControl.FileSystemRights]) | foreach{
        ##$Table = @{
            ##"Name"=$($_.ToString());`
            ##"Value"=$($($_).value__)
        ##}
        ##New-Object psobject -pr $Table | select "Name","Value"
    ##}

    #Create Hash Table
    $FileSystemRightsEnumHT = @{}

    #Call the FileSystemRights enumeration and add each one to the hash table
    [System.Enum]::GetValues([System.Security.AccessControl.FileSystemRights]) | foreach{
        $FileSystemRightsEnumHT[$($_.ToString())]=$($($_).value__)
    }

    #There are a few permissions in the above enumeration that are bit combinations, i.e. they
    #contain multiple bits and are a combination of several permissions
    #Write ---------- 278
        #CreateFiles ------------- 2
        #AppendData -------------- 4                
        #WriteExtendedAttributes - 16
        #WriteAttributes --------- 256
                
    #Read ----------- 131209
        #ReadData ---------------- 1
        #ReadExtendedAttributes -- 8
        #ReadAttributes ---------- 128
        #ReadPermissions --------- 131072

    #ReadAndExecute - 131241
        #ReadData ---------------- 1
        #ReadExtendedAttributes -- 8
        #ExecuteFile ------------- 32
        #ReadAttributes ---------- 128
        #ReadPermissions --------- 131072

    #Modify --------- 197055
        #ReadData ---------------- 1
        #CreateFiles ------------- 2
        #AppendData -------------- 4
        #ReadExtendedAttributes -- 8
        #WriteExtendedAttributes - 16
        #ExecuteFile ------------- 32
        #ReadAttributes ---------- 128
        #WriteAttributes --------- 256
        #Delete ------------------ 65536
        #ReadPermissions --------- 131072                
                
                
    #We need a way to determine if one of these combination permissions is set. Basically, we can gather all matching enumerated permissions, and
        #then loop through the matching permissions, and see if there are any bitwise matches inside the list of matching permissions.
            
            
            


    #We can use the Bitwise Exclusive OR comparison operator (-bxor) to remove a matching permission bit, so we can tell
    #what bits are left to match.
    #With -bxor, the resulting bit is set to 1 only when one input bit is 1.
    #So, for example, let's say our permission number happens to be something strange, like 50331904, which would be these permission constants:
                        
    #FILE_WRITE_ATTRIBUTES -- 256
    #ACCESS_SYSTEM_SECURITY - 16777216
    #MAXIMUM_ALLOWED -------- 33554432

    #If we run the number 50331904 through our Enumeration hash table above, we will match the FILE_WRITE_ATTRIBUTES permission to the WriteAttributes
        #permission in the hash table. However, we would not match either the ACCESS_SYSTEM_SECURITY or the MAXIMUM_ALLOWED permission, and we would want
        #to know that.

        #I mean, in reality, the ACCESS_SYSTEM_SECURITY or the MAXIMUM_ALLOWED permission can't be applied in a DACL, so they're not really of concern, but
        #we would still want to know if they were somehow present.

    #FYI, to determine if there are any permissions left, we can use the -bxor operator, which would basically compare the bits of 2 integers, and only keeps
        #the bits where only one of the 2 numbers is 0. For example, if we did a -bxor of these 2 numbers:
            #1110 (14)
            #0100 (4)
            #--------- (-bxor)
            #1010 (10)
        #the result would be 10, as it only keeps 1's where only one of the input bits is 1 (essentially it removed bits where both input bits are 1).

    #So, since we matched the FILE_WRITE_ATTRIBUTES permission to the WriteAttributes permission in the hash table, we can do a -bxor of that value
        #against the original decimal value. So, we would do 50331904 -bxor 256, which would be 50331648. In this way, we can tell if there are any
        #permissions that are leftover after we compare the decimal to our enumeration hash table above.

    #endregion

    ########################################
    #region   Access_Mask Constants Hash Table   #
    ########################################
    #OBJECT SPECIFIC permissions - #https://msdn.microsoft.com/en-us/library/aa394063(v=vs.85).aspx
    #STANDARD permissions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa379607(v=vs.85).aspx
    #GENERIC permissions - #https://msdn.microsoft.com/en-us/library/aa364399.aspx


    #The following link provides code to see the name and alias name of the rights enumerations from above:
    #https://stackoverflow.com/questions/27529174/how-can-i-compare-against-filesystemrights-using-powershell
    ##[System.Enum]::GetNames([System.Security.AccessControl.FileSystemRights]) | foreach{
        ##"$($_.ToString())`t`t$([System.Security.AccessControl.FileSystemRights]$_.ToString())`t`t$(([System.Security.AccessControl.FileSystemRights]$_).value__)";
    ##}

    #I have put the output from the above 3 lines of commented code in the below table for reference beside the AccessMask Constant names

                                                ###############################################################################
    $AccessMaskConstantsHT = @{                  # Bit #     FileSystemRightsEnum Name     #     FileSystemRightsEnum Alias    #
                                                    #-----#-----------------------------------#-----------------------------------#
        #OBJECT SPECIFIC permissions             #     #                                   #                                   #
        "FILE_READ_DATA"=1;                      #  0  # ReadData                          # ReadData                          #     
        "FILE_LIST_DIRECTORY"=1;                 #  0  # ReadData                          # ListDirectory                     #
        "FILE_WRITE_DATA"=2;                     #  1  # CreateFiles                       # WriteData                         #
        "FILE_ADD_FILE"=2;                       #  1  # CreateFiles                       # CreateFiles                       #
        "FILE_APPEND_DATA"=4;                    #  2  # AppendData                        # AppendData                        #
        "FILE_ADD_SUBDIRECTORY"=4;               #  2  # AppendData                        # CreateDirectories                 #
        "FILE_READ_EA"=8;                        #  3  # ReadExtendedAttributes            # ReadExtendedAttributes            #
        "FILE_WRITE_EA"=16;                      #  4  # WriteExtendedAttributes           # WriteExtendedAttributes           #
        "FILE_EXECUTE"=32;                       #  5  # ExecuteFile                       # ExecuteFile                       #
        "FILE_TRAVERSE"=32;                      #  5  # ExecuteFile                       # Traverse                          #
        "FILE_DELETE_CHILD"=64;                  #  6  # DeleteSubdirectoriesAndFiles      # DeleteSubdirectoriesAndFiles      #
        "FILE_READ_ATTRIBUTES"=128;              #  7  # ReadAttributes                    # ReadAttributes                    #
        "FILE_WRITE_ATTRIBUTES"=256;             #  8  # WriteAttributes                   # WriteAttributes                   #
        #Unused                                  #  9  #                                   #                                   #
        #Unused                                  #  10 #                                   #                                   #
        #Unused                                  #  11 #                                   #                                   #
        #Unused                                  #  12 #                                   #                                   #
        #Unused                                  #  13 #                                   #                                   #
        #Unused                                  #  14 #                                   #                                   #
        #Unused                                  #  15 #                                   #                                   #
                                                    #     #                                   #                                   #
        #STANDARD permissions                    #     #                                   #                                   #
        "DELETE"=65536;                          #  16 # Delete                            # Delete                            #
        "READ_CONTROL"=131072;                   #  17 # ReadPermissions                   # ReadPermissions                   #
        "STANDARD_RIGHTS_EXECUTE"=131072;        #  17 # ReadPermissions                   # ReadPermissions                   #
        "STANDARD_RIGHTS_WRITE"=131072;          #  17 # ReadPermissions                   # ReadPermissions                   #
        "STANDARD_RIGHTS_READ"=131072;           #  17 # ReadPermissions                   # ReadPermissions                   #
        "WRITE_DAC"=262144;                      #  18 # ChangePermissions                 # ChangePermissions                 #
        "WRITE_OWNER"=524288;                    #  19 # TakeOwnership                     # TakeOwnership                     #
        "SYNCHRONIZE"=1048576;                   #  20 # Synchronize                       # Synchronize                       #
        #Unused                                  #  21 #                                   #                                   #
        #Unused                                  #  22 #                                   #                                   #
        #Unused                                  #  23 #                                   #                                   #
                                                     #     #                                   #                                   #
        "ACCESS_SYSTEM_SECURITY"=16777216;       #  24 #                                   #                                   # Allows access to a System Access Control List (SACL) via the SE_SECURITY_NAME privilege - https://msdn.microsoft.com/en-us/library/windows/desktop/aa374892(v=vs.85).aspx - This access right is not valid in a DACL because DACLs do not control access to a SACL. - https://msdn.microsoft.com/en-us/library/windows/desktop/aa379321(v=vs.85).aspx
        "MAXIMUM_ALLOWED"=33554432               #  25 #                                   #                                   # This bit cannot be set in an ACE - https://msdn.microsoft.com/en-us/library/cc230294.aspx - this is basically used in the AccessCheck function to check the Maximum Allowed Permissions allowed to the requestor.
                                                    #     #                                   #                                   #
        #RESERVED                                #     #                                   #                                   #
        #Unused                                  #  26 #                                   #                                   #
        #Unused                                  #  27 #                                   #                                   #
                                                    #     #                                   #                                   #
        #GENERIC permissions                     #     #                                   #                                   #
        "GENERIC_ALL"=268435456;                 #  28 #                                   #                                   #
        "GENERIC_EXECUTE"=536870912;             #  29 #                                   #                                   #
            #GENERIC_EXECUTE contains:           #     #                                   #                                   #
                #FILE_EXECUTE            32      #     # ExecuteFile                       # ExecuteFile                       #
                #FILE_READ_ATTRIBUTES    128     #     # ReadAttributes                    # ReadAttributes                    #
                #STANDARD_RIGHTS_EXECUTE 131072  #     # ReadPermissions                   # ReadPermissions                   #
                #SYNCHRONIZE             1048576 #     # Synchronize                       # Synchronize                       #
                                                    #     #                                   #                                   #
        "GENERIC_WRITE"=1073741824;              #  30 #                                   #                                   #
            #GENERIC_WRITE contains:             #     #                                   #                                   #
                #FILE_APPEND_DATA        4       #     # AppendData                        # AppendData                        #
                #FILE_WRITE_ATTRIBUTES   256     #     # WriteAttributes                   # WriteAttributes                   #
                #FILE_WRITE_DATA         2       #     # CreateFiles                       # WriteData                         #  
                #FILE_WRITE_EA           16      #     # WriteExtendedAttributes           # WriteExtendedAttributes           #
                #STANDARD_RIGHTS_WRITE   131072  #     # ReadPermissions                   # ReadPermissions                   #
                #SYNCHRONIZE             1048576 #     # Synchronize                       # Synchronize                       #
                                                    #     #                                   #                                   #
        "GENERIC_READ"=2147483648;               #  31 #                                   #                                   #
            #GENERIC_READ contains:              #     #                                   #                                   #
                #FILE_READ_ATTRIBUTES    128     #     # ReadAttributes                    # ReadAttributes                    #
                #FILE_READ_DATA          1       #     # ReadData                          # ReadData                          #
                #FILE_READ_EA            8       #     # ReadExtendedAttributes            # ReadExtendedAttributes            #
                #STANDARD_RIGHTS_READ    131072  #     # ReadPermissions                   # ReadPermissions                   #
                #SYNCHRONIZE             1048576 #     # Synchronize                       # Synchronize                       #
                                                    ###############################################################################
    }

    #endregion

    #########################################
    #region   GENERIC Constant Names Hash Table   #
    #########################################
    #We need a hash table of the above GENERIC permissions, since they are a combination of many Constants. And since they are a
    #combination of many constants, we will define each one as an array.

    $AccessMaskConstantsHTGENERIC = @{
        "GENERIC_EXECUTE"=@{
                "FILE_EXECUTE"=$AccessMaskConstantsHT["FILE_EXECUTE"];
                "FILE_READ_ATTRIBUTES"=$AccessMaskConstantsHT["FILE_READ_ATTRIBUTES"];
                "STANDARD_RIGHTS_EXECUTE"=$AccessMaskConstantsHT["STANDARD_RIGHTS_EXECUTE"];
                "SYNCHRONIZE"=$AccessMaskConstantsHT["SYNCHRONIZE"];
        };
        "GENERIC_READ"=@{
                "FILE_READ_ATTRIBUTES"=$AccessMaskConstantsHT["FILE_READ_ATTRIBUTES"];
                "FILE_READ_DATA"=$AccessMaskConstantsHT["FILE_READ_DATA"];
                "FILE_READ_EA"=$AccessMaskConstantsHT["FILE_READ_EA"];
                "STANDARD_RIGHTS_READ"=$AccessMaskConstantsHT["STANDARD_RIGHTS_READ"];
                "SYNCHRONIZE"=$AccessMaskConstantsHT["SYNCHRONIZE"];
        };
        "GENERIC_WRITE"=@{
                "FILE_APPEND_DATA"=$AccessMaskConstantsHT["FILE_APPEND_DATA"];
                "FILE_WRITE_ATTRIBUTES"=$AccessMaskConstantsHT["FILE_WRITE_ATTRIBUTES"];
                "FILE_WRITE_DATA"=$AccessMaskConstantsHT["FILE_WRITE_DATA"];
                "FILE_WRITE_EA"=$AccessMaskConstantsHT["FILE_WRITE_EA"];
                "STANDARD_RIGHTS_WRITE"=$AccessMaskConstantsHT["STANDARD_RIGHTS_WRITE"];
                "SYNCHRONIZE"=$AccessMaskConstantsHT["SYNCHRONIZE"];
        };
        #No need to add the value of GENERIC_ALL, as we just check for the name below
        "GENERIC_ALL"=@{"GENERIC_ALL"="GENERIC_ALL"}
    }

    #endregion
    
    ################################################################################################

    $FileSystemRightsNumInitial = $FileSystemRights
    $FileSystemRightsNumFinal = 0

    $AccessMaskConstantsNumInitial = 0


    $FileSystemRightsArrayInitial = @{}
    $FileSystemRightsArrayFinal = @()
    $ConstantNamesInitial = @()
    $ConstantNamesHTFinal = @{}
    $ConstantNamesNotMatchedToEnumHT = @{}


    ##############################################
    #region   1. Get AccessMask Constant Permissions   #
    ##############################################
        #So, since the integer values for FileSystemRights are probably due to AccessMask Constant values, we want to run
            #the integer through the Constant hash table first to get the names of the permissions that are in the integer.

        #For example, let's say our FileSystemRights integer is 3238002688. We will run the number through the below command to
            #give us the Constant names of the permissions in the integer:

        $ConstantNamesInitial = $AccessMaskConstantsHT.Keys | ?{($AccessMaskConstantsHT["$_"] -band $FileSystemRightsNumInitial) -eq $AccessMaskConstantsHT["$_"]}

        #In our example, the FileSystemRights integer of 3238002688 gives us these permissions:
            #GENERIC_WRITE
            #ACCESS_SYSTEM_SECURITY
            #GENERIC_READ

    #endregion

    #################################################
    #region   2. Expand AccessMask Constant Permissions   #
    #################################################
    #Now that we have our list of Constant names, we want to find the matching enumeration names that FileSystemRights uses.

    #First, we want to check our list of Constant permissions to see if there are any GENERIC permissions, as these are a combination
        #of many permissions. We want to find the lower Constant names that are in each GENERIC permission.    
    

    If($ConstantNamesInitial){
        foreach($ConstantNameInitial in $ConstantNamesInitial){
            #IF it matches a GENERIC permission, then expand the GENERIC permission and add each expanded Constant name to the final array
            If($ConstantNameInitial -match "GENERIC_"){
                
                #Since several of the GENERIC permission sets contain some of the same permission names (like SYNCHRONIZE) or some
                    #of the same permission values (like STANDARD_RIGHTS_READ and STANDARD_RIGHTS_WRITE), we need to loop through the
                    #hash table and only add those entries where the key or value doesn't already exist.
                $AccessMaskConstantsHTGENERIC[$ConstantNameInitial].GetEnumerator() | foreach{                    
                    #write-host "current name: $($_.key)"
                    $CurrentHTEntry = @{$_.key=$_.value}
                    
                    If(!($ConstantNamesHTFinal.keys -contains $_.key) -and !($ConstantNamesHTFinal.values -contains $_.value)){
                        $ConstantNamesHTFinal += $CurrentHTEntry
                    }                    
                }
            }
            #If it's not a GENERIC permission, then just add the Constant name to the array.
            Else{
                $ConstantNamesHTFinal += @{$ConstantNameInitial=$AccessMaskConstantsHT[$ConstantNameInitial]}
            }
        }
    }

    #So, for our example, we started with the FileSystemRights integer of 3238002688, which gave us these 3 Constant permissions:
        #GENERIC_WRITE
        #ACCESS_SYSTEM_SECURITY
        #GENERIC_READ

    #Just now, we expanded the GENERIC ones, to give us this final hash-table list in $ConstantNamesHTFinal:

    #Name                           Value                                                                                                                                                     
    #----                           -----                                                                                                                                                     
    #FILE_APPEND_DATA               4                                                                                                                                                         
    #ACCESS_SYSTEM_SECURITY         16777216                                                                                                                                                  
    #SYNCHRONIZE                    1048576                                                                                                                                                   
    #FILE_READ_ATTRIBUTES           128                                                                                                                                                       
    #STANDARD_RIGHTS_WRITE          131072                                                                                                                                                    
    #FILE_WRITE_DATA                2                                                                                                                                                         
    #FILE_WRITE_ATTRIBUTES          256                                                                                                                                                       
    #FILE_READ_EA                   8                                                                                                                                                         
    #FILE_READ_DATA                 1                                                                                                                                                         
    #FILE_WRITE_EA                  16  

    #endregion

    ##########################################################################
    #region   If GENERIC_ALL permission was applied, skip the rest of the checks   #
    ##########################################################################
    #So, if GENERIC_ALL was set, we don't have to do any more work, as this Constant permission is the same
    #thing as FullControl, so we don't have to worry about any granular permissions, as FullControl is of course
    #every permission.
    $GENERICALLSet = $false
    $ConstantNamesHTFinal.GetEnumerator() | foreach{
        If($_.name -eq "GENERIC_ALL"){
            $GENERICALLSet = $true
        }
    }

    If($GENERICALLSet)
    {
        $FileSystemRightsArrayFinal += "FullControl"
    }

    #endregion

    #############################################################################################
    #region   If GENERIC_ALL permission was NOT applied, begin enumerating the Constant permisisons   #
    #############################################################################################
    #So, if GENERIC_ALL was not set, we do need to enumerate the permissions further

    Else
    {
        ###############################################################
        #region   3. Match expanded Constant names with Enumeration names   #
        ###############################################################
    
        #First, get the decimal value of all the permissions in the Constants array
            #Here, as shown above, $ConstantNamesHTFinal is a hash table containing the names and decimal values of the AccessMask Constants that
            #are in the permissions
        $ConstantNamesHTFinal.GetEnumerator() | foreach{
            #$AccessMaskConstantsHT[$_]
            $AccessMaskConstantsNumInitial = $AccessMaskConstantsNumInitial + $AccessMaskConstantsHT[$_.name]
        }
    
        #write-host "Initial value of AccessMaskConstantsNumInitial is $AccessMaskConstantsNumInitial" -ForegroundColor Cyan
        foreach($ConstantNameFinal in $ConstantNamesHTFinal.GetEnumerator()){        

            #We want to gather all the Enumeration names (the EnumHT keys), and find any whose value matches the current Constant name value
            $FileSystemRightsEnumHT.Keys | ?{($FileSystemRightsEnumHT["$_"] -band $AccessMaskConstantsHT[$ConstantNameFinal.Name]) -eq $FileSystemRightsEnumHT["$_"]} | foreach{            
                $CurrentName = $_
                $CurrentValue = $FileSystemRightsEnumHT["$_"]
                $CurrentHTEntry = @{$CurrentName=$CurrentValue}
                #If the $FileSystemRightsArrayInitial array doesn't already contain the enumeration value, then add it
                If(!($FileSystemRightsArrayInitial.keys -contains $CurrentHTEntry.keys)){
                    $FileSystemRightsArrayInitial += $CurrentHTEntry

                    #"Subtract" the current permission decimal value from the total decimal value. That way, when this loop is finished, we can see if
                    #we have any leftover decimal value left. If we do, that means there was a Constant permission that was not matched to an Enumeration.
                    #write-host "`nEnumerated value $_ is not in the FileSystemRightsArrayInitial hash table. Removing $CurrentValue from AccessMaskConstantsNumInitial value of $AccessMaskConstantsNumInitial" -ForegroundColor Cyan

                    $AccessMaskConstantsNumInitial = [int]$AccessMaskConstantsNumInitial -bxor [int]$CurrentValue
                
                    #Add the decimal value of the enumerated permission to the "final" tracking variable
                        #This variable will contain the total decimal number of all matching enumerated permissions
                    $FileSystemRightsNumFinal = $FileSystemRightsNumFinal + $CurrentValue
                
                }
            }
        }
        #So, for our example, we started with the FileSystemRights integer of 3238002688, which gave us these 3 Constant permissions:
            #GENERIC_WRITE
            #ACCESS_SYSTEM_SECURITY
            #GENERIC_READ

        #Earlier, we expanded the GENERIC ones, to give us this final hash-table list in $ConstantNamesHTFinal:

            #Name                           Value                                                                                                                                                     
            #----                           -----                                                                                                                                                     
            #FILE_APPEND_DATA               4                                                                                                                                                         
            #ACCESS_SYSTEM_SECURITY         16777216                                                                                                                                                  
            #SYNCHRONIZE                    1048576                                                                                                                                                   
            #FILE_READ_ATTRIBUTES           128                                                                                                                                                       
            #STANDARD_RIGHTS_WRITE          131072                                                                                                                                                    
            #FILE_WRITE_DATA                2                                                                                                                                                         
            #FILE_WRITE_ATTRIBUTES          256                                                                                                                                                       
            #FILE_READ_EA                   8                                                                                                                                                         
            #FILE_READ_DATA                 1                                                                                                                                                         
            #FILE_WRITE_EA                  16 

        #Now, just above, we matched the above expanded Constant permissions to their equivalent Enumerated permissions:

            #Name                           Value                                                                                                                                                     
            #----                           -----                                                                                                                                                     
            #ReadData                       1                                                                                                                                                         
            #CreateFiles                    2                                                                                                                                                         
            #ReadPermissions                131072                                                                                                                                                    
            #Synchronize                    1048576                                                                                                                                                   
            #ReadExtendedAttributes         8                                                                                                                                                         
            #WriteAttributes                256                                                                                                                                                       
            #ReadAttributes                 128                                                                                                                                                       
            #WriteExtendedAttributes        16                                                                                                                                                        
            #AppendData                     4    

        #endregion

        ###################################################################################
        #region   Record any Constant permissions that didn't match an Enumeration permission   #
        ###################################################################################

        #If we had any decimal value leftover from the initial value, that means there was a Constant permission that was not matched to an Enumeration permission above.    
        If($AccessMaskConstantsNumInitial -ne 0){          
            $AccessMaskConstantsHT.Keys | ?{($AccessMaskConstantsHT["$_"] -band $AccessMaskConstantsNumInitial) -eq $AccessMaskConstantsHT["$_"]} | foreach{

                $ConstantNamesNotMatchedToEnumHT += @{$_=$AccessMaskConstantsHT[$_]}

                #Remove the current matched Constant permission decimal value from the tracking variable
                $AccessMaskConstantsNumInitial = [int]$AccessMaskConstantsNumInitial -bxor [int]$AccessMaskConstantsHT["$_"]
            }
            
            If($ConstantNamesNotMatchedToEnumHT){
                write-host "`nINFORMATION: The following AccessMask Constant permissions were present that do not match to a FileSystemRights enumeration permission (bit match):" -ForegroundColor Yellow
                $ConstantNamesNotMatchedToEnumHT
                                                        
            }

            #So, if the decimal tracking variable is still not 0, that means there was some decimal value leftover that didn't
                #match any Constant or Enumeration permission, so we will just make that known, but we will likely leave it out of
                #the final permission, as it doesn't match to anything anyway.

            If($AccessMaskConstantsNumInitial -ne 0){
                write-host "`nINFORMATION: After performing all permission matching operations, the following decimal value was leftover, which does not match any AccessMask Constant permission, or a FileSystemRights Enumeration permission:" -ForegroundColor Yellow
                $AccessMaskConstantsNumInitial
            }
        }
        #In our example, we were left with the decimal value of 16777216, so above, in our example the $ConstantNamesNotMatchedToEnumHT would be:
            #Name                           Value                                                                                                                                                     
            #----                           -----                                                                                                                                                     
            #ACCESS_SYSTEM_SECURITY         16777216 
                                                
        #Again, any permission or decimal leftover that didn't match an Enumeration value can't be used in a DACL, so it's no concern to us, 
        #but it's just informational.

        #endregion

        #########################################################
        #region   4. Combine Enumeration permissions where possible   #
        #########################################################
        #Here, we want to combine any enumerated permissions that we can, i.e. if all the Read sub-permissions are present, combine them into the single Read permission:
            #Read ----------- 131209
                    #ReadData ---------------- 1
                    #ReadExtendedAttributes -- 8
                    #ReadAttributes ---------- 128
                    #ReadPermissions --------- 131072

    
        #So, we're going to sort the reference enumeration hash table by highest value first, and then do bit matching against the final total enumeration value, then subtract the
            #matching decimal value from the number.

        $FileSystemRightsEnumHT = $FileSystemRightsEnumHT.GetEnumerator() | Sort-Object value -Descending

        #Now, loop through the reference enumeration hash table and see what permissions bitwise-match the final decimal value, then subtract that value from the decimal value
        $FileSystemRightsEnumHT.GetEnumerator() | foreach{        
            If(($FileSystemRightsNumFinal -band $_.value) -eq $_.value){
                $FileSystemRightsArrayFinal += $_.key
                $FileSystemRightsNumFinal = $FileSystemRightsNumFinal - $_.value
            }
        }  
        #So, for our example, we started with the FileSystemRights integer of 3238002688, which gave us these 3 Constant permissions:
            #GENERIC_WRITE
            #ACCESS_SYSTEM_SECURITY
            #GENERIC_READ

        #Earlier, we expanded the GENERIC ones, to give us this final hash-table list in $ConstantNamesHTFinal:

            #Name                           Value                                                                                                                                                     
            #----                           -----                                                                                                                                                     
            #FILE_APPEND_DATA               4                                                                                                                                                         
            #ACCESS_SYSTEM_SECURITY         16777216                                                                                                                                                  
            #SYNCHRONIZE                    1048576                                                                                                                                                   
            #FILE_READ_ATTRIBUTES           128                                                                                                                                                       
            #STANDARD_RIGHTS_WRITE          131072                                                                                                                                                    
            #FILE_WRITE_DATA                2                                                                                                                                                         
            #FILE_WRITE_ATTRIBUTES          256                                                                                                                                                       
            #FILE_READ_EA                   8                                                                                                                                                         
            #FILE_READ_DATA                 1                                                                                                                                                         
            #FILE_WRITE_EA                  16 

        #Also earlier, we matched the above expanded Constant permissions to their equivalent Enumerated permissions:

            #Name                           Value                                                                                                                                                     
            #----                           -----                                                                                                                                                     
            #ReadData                       1                                                                                                                                                         
            #CreateFiles                    2                                                                                                                                                         
            #ReadPermissions                131072                                                                                                                                                    
            #Synchronize                    1048576                                                                                                                                                   
            #ReadExtendedAttributes         8                                                                                                                                                         
            #WriteAttributes                256                                                                                                                                                       
            #ReadAttributes                 128                                                                                                                                                       
            #WriteExtendedAttributes        16                                                                                                                                                        
            #AppendData                     4  

        #Just now, we condensed the Enumerated permissions into the variable $FileSystemRightsArrayFinal:

            #Synchronize
            #Read
            #Write

        #endregion
                
    }#End of if the AccessMask Constant permissions did NOT include GENERIC_ALL   
                                                                                                                            
    #endregion
    #So, in our example above, $FileSystemRights will be "Synchronize,Read,Write"
    $FileSystemRights = $FileSystemRightsArrayFinal -join ", "
                                        
    write-verbose "The final list of FileSystemEnumeration permissions for integer $FileSystemRightsInteger are: $FileSystemRights"                         

    $FileSystemRights
    }
    catch
    {
        $ErrorMessage = "Could not convert file system rights '{0}': '{1}'." -f $FileSystemRightsInteger, $_.Exception.Message
        Write-Error -Exception $_.Exception -Message $ErrorMessage
        return
    }
}


#endregion
