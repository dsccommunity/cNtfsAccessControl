#requires -Version 4.0

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
        [Boolean]
        $Enabled,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $PreserveInherited = $false
    )

    $PSBoundParameters.GetEnumerator() |
    ForEach-Object -Begin {
        $Width = $PSBoundParameters.Keys.Length | Sort-Object -Descending | Select-Object -First 1
    } -Process {
        "{0,-$($Width)} : '{1}'" -f $_.Key, ($_.Value -join ', ') |
        Write-Verbose
    }

    $Acl = Get-Acl -Path $Path -ErrorAction Stop

    $EnabledResult = $Acl.AreAccessRulesProtected -eq $false

    if ($EnabledResult -eq $true)
    {
        Write-Verbose -Message "Permissions inheritance is enabled on path '$Path'."
    }
    else
    {
        Write-Verbose -Message "Permissions inheritance is disabled on path '$Path'."
    }

    $ReturnValue = @{
            Path = $Path
            Enabled = $EnabledResult
            PreserveInherited = $PreserveInherited
        }

    return $ReturnValue
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [Boolean]
        $Enabled,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $PreserveInherited = $false
    )

    $TargetResource = Get-TargetResource @PSBoundParameters

    $InDesiredState = $Enabled -eq $TargetResource.Enabled

    if ($InDesiredState -eq $true)
    {
        Write-Verbose -Message "The target resource is already in the desired state. No action is required."
    }
    else
    {
        Write-Verbose -Message "The target resource is not in the desired state."
    }

    return $InDesiredState
}

function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [Boolean]
        $Enabled,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $PreserveInherited = $false
    )

    $Acl = Get-Acl -Path $Path -ErrorAction Stop

    if ($Enabled -eq $false)
    {
        Write-Verbose -Message "Disabling permissions inheritance on path '$Path'."

        if ($PreserveInherited -eq $true)
        {
            Write-Verbose -Message 'Inherited permissions will be converted to expicit permissions.'
        }
        else
        {
            Write-Verbose -Message 'Inherited permissions will be removed.'
        }

        $Acl.SetAccessRuleProtection($true, $PreserveInherited)
    }
    else
    {
        Write-Verbose -Message "Enabling permissions inheritance on path '$Path'."

        $Acl.SetAccessRuleProtection($false, $false)
    }

    if ($PSCmdlet.ShouldProcess($Path, 'SetAccessControl'))
    {
        # The Set-Acl cmdlet is not used on purpose
        if ($Acl -is [System.Security.AccessControl.DirectorySecurity])
        {
            [System.IO.Directory]::SetAccessControl($Path, $Acl)
        }
        else
        {
            [System.IO.File]::SetAccessControl($Path, $Acl)
        }
    }
}

Export-ModuleMember -Function *-TargetResource
