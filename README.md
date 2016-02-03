# cNtfsAccessControl

The **cNtfsAccessControl** module contains DSC Resources for NTFS access control management.

You can also download this module from the [PowerShell Gallery](https://www.powershellgallery.com/packages/cNtfsAccessControl/).

## Resources

### cNtfsPermissionEntry

The **cNtfsPermissionEntry** DSC resource provides a mechanism to manage NTFS permissions.

* **Ensure**: Indicates if the permission entry exists. The default value is `Present`. Set this property to `Absent` to ensure that any explicit access rights the principal has are revoked.
* **Path**: Indicates the path to the target item.
* **ItemType**: Indicates whether the target item is a `Directory` or a `File`.
* **Principal**: Indicates the identity of the principal. Valid formats are:
    * [User Principal Name (UPN)](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380525%28v=vs.85%29.aspx#user_principal_name)
    * [Down-Level Logon Name](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380525%28v=vs.85%29.aspx#down_level_logon_name)
    * [Security Accounts Manager (SAM) Account Name (sAMAccountName)](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679635%28v=vs.85%29.aspx)
    * [Security Identifier (SID)](https://msdn.microsoft.com/en-us/library/cc246018.aspx)
* **AccessControlInformation**: Indicates the collection of instances of the custom **cNtfsAccessControlInformation** CIM class that implements the following properties:
    * **AccessControlType**: Indicates whether to `Allow` or `Deny` access to the target item.
    * **FileSystemRights**: Indicates the access rights to be granted to the principal. Specify one or more values from the [System.Security.AccessControl.FileSystemRights](https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights%28v=vs.110%29.aspx) enumeration type. Multiple values can be specified by using an array of strings or a single comma-separated string.
    * **Inheritance**: Apply to. This property is only valid when the **ItemType** property is set to `Directory`. Valid values are:
        * `None`
        * `ThisFolderOnly`
        * `ThisFolderSubfoldersAndFiles`
        * `ThisFolderAndSubfolders`
        * `ThisFolderAndFiles`
        * `SubfoldersAndFilesOnly`
        * `SubfoldersOnly`
        * `FilesOnly`
    * **NoPropagateInherit**: Only apply these permissions to objects and/or containers within this container. This property is only valid when the **ItemType** property is set to `Directory`.

#### Notes

> If the **Ensure** property is set to `Absent`, the **AccessControlInformation** property is ignored. Any explicit access rights the principal has are revoked.

> If the **Ensure** property is set to `Present` and the **AccessControlInformation** property is not specified, the default permission entry will be used as the reference entry.
 Default values are:

| ItemType  | AccessControlType | FileSystemRights | Inheritance                  |
|-----------|-------------------|------------------|------------------------------|
| Directory | Allow             | ReadAndExecute   | ThisFolderSubfoldersAndFiles |
| File      | Allow             | ReadAndExecute   | None                         |

> If you want to assign multiple permission entries for a principal, it is strongly recommended to test them in advance to make sure they are not merging.
 In such cases the **Test-TargetResource** function will always return `$false` (i.e. resource is not in the desired state), and permissions will be reapplied every time DSC consistency check is executed.

### cNtfsPermissionsInheritance

The **cNtfsPermissionsInheritance** DSC resource provides a mechanism to manage NTFS permissions inheritance.

* **Path**: Indicates the path to the target item.
* **Enabled**: Indicates whether permissions inheritance is enabled. Set this property to `$false` to ensure permissions inheritance is disabled.
* **PreserveInherited**: Indicates whether to preserve inherited permissions. Set this property to `$true` to convert inherited permissions into explicit permissions. The default value is `$false`. This property is ignored if **Enabled** is set to `$true`.

## Versions

### Unreleased

* The **cNtfsPermissionsInheritance** resource was added.

### 1.1.1 (October 15, 2015)

* Minor update.

### 1.1.0 (September 30, 2015)

* The **PermissionEntry** property was renamed to **AccessControlInformation**.

### 1.0.0 (September 29, 2015)

* Initial release with the following resources:
  * **cNtfsPermissionEntry**

## Examples

### Assign NTFS permissions

This example shows how to use the cNtfsPermissionEntry DSC resource to assign NTFS permissions.

```powershell
<#
.SYNOPSIS
    Assign NTFS permissions.
.DESCRIPTION
    This example shows how to use the cNtfsPermissionEntry DSC resource to assign NTFS permissions.
#>

Configuration Sample_cNtfsPermissionEntry
{
    Import-DscResource -ModuleName cNtfsAccessControl
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    File TestDirectory
    {
        Ensure          = 'Present'
        DestinationPath = 'C:\TestDirectory'
        Type            = 'Directory'
    }

    # Grant a single permission
    cNtfsPermissionEntry PermissionEntry1
    {
        Ensure    = 'Present'
        Path      = 'C:\TestDirectory'
        ItemType  = 'Directory'
        Principal = 'BUILTIN\Power Users'
        AccessControlInformation =
        @(
            cNtfsAccessControlInformation
            {
                AccessControlType  = 'Allow'
                FileSystemRights   = 'ReadAndExecute'
                Inheritance        = 'ThisFolderSubfoldersAndFiles'
                NoPropagateInherit = $false
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # Grant multiple permissions at a time
    cNtfsPermissionEntry PermissionEntry2
    {
        Ensure    = 'Present'
        Path      = 'C:\TestDirectory'
        ItemType  = 'Directory'
        Principal = 'BUILTIN\Administrators'
        AccessControlInformation =
        @(
            cNtfsAccessControlInformation
            {
                AccessControlType  = 'Allow'
                FileSystemRights   = 'Modify'
                Inheritance        = 'ThisFolderOnly'
                NoPropagateInherit = $false
            }

            cNtfsAccessControlInformation
            {
                AccessControlType  = 'Allow'
                FileSystemRights   = 'ReadAndExecute'
                Inheritance        = 'ThisFolderSubfoldersAndFiles'
                NoPropagateInherit = $false
            }

            cNtfsAccessControlInformation
            {
                AccessControlType  = 'Allow'
                FileSystemRights   = 'AppendData', 'CreateFiles'
                Inheritance        = 'SubfoldersAndFilesOnly'
                NoPropagateInherit = $false
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # Revoke all explicit permissions
    cNtfsPermissionEntry PermissionEntry3
    {
        Ensure    = 'Absent'
        Path      = 'C:\TestDirectory'
        ItemType  = 'Directory'
        Principal = 'BUILTIN\Users'
        DependsOn = '[File]TestDirectory'
    }
}

Sample_cNtfsPermissionEntry -OutputPath "$Env:SystemDrive\Sample_cNtfsPermissionEntry"

Start-DscConfiguration -Path "$Env:SystemDrive\Sample_cNtfsPermissionEntry" -Force -Verbose -Wait

Get-DscConfiguration

```

### Disable NTFS permissions inheritance

This example shows how to use the cNtfsPermissionsInheritance DSC resource to disable NTFS permissions inheritance.

```powershell

Configuration Sample_cNtfsPermissionsInheritance
{
    Import-DscResource -ModuleName cNtfsAccessControl
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    File TestDirectory
    {
        Ensure          = 'Present'
        DestinationPath = 'C:\TestDirectory'
        Type            = 'Directory'
    }

    # Disable permissions inheritance
    cNtfsPermissionsInheritance DisableInheritance
    {
        Path              = 'C:\TestDirectory'
        Enabled           = $false
        PreserveInherited = $true
        DependsOn         = '[File]TestDirectory'
    }
}

Sample_cNtfsPermissionsInheritance -OutputPath "$Env:SystemDrive\Sample_cNtfsPermissionsInheritance"

Start-DscConfiguration -Path "$Env:SystemDrive\Sample_cNtfsPermissionsInheritance" -Force -Verbose -Wait

Get-DscConfiguration

```
