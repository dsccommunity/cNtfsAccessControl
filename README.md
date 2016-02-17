[![Build status](https://ci.appveyor.com/api/projects/status/olfva3iu8lcehhf1?svg=true)](https://ci.appveyor.com/project/SNikalaichyk/cNtfsAccessControl)

# cNtfsAccessControl

The **cNtfsAccessControl** module contains DSC resources for NTFS access control management.

You can also download this module from the [PowerShell Gallery](https://www.powershellgallery.com/packages/cNtfsAccessControl/).

## Resources

### cNtfsPermissionEntry

The **cNtfsPermissionEntry** DSC resource provides a mechanism to manage NTFS permissions.

* **Ensure**: Indicates if the permission entry exists. Set this property to `Absent` to ensure that all explicit permissions associated with the specified principal are removed. The default value is `Present`.
* **Path**: Indicates the path to the target item.
* **Principal**: Indicates the identity of the principal. Valid formats are:
    * [Down-Level Logon Name](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380525%28v=vs.85%29.aspx#down_level_logon_name)
    * [Security Accounts Manager (SAM) Account Name (sAMAccountName)](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679635%28v=vs.85%29.aspx)
    * [Security Identifier (SID)](https://msdn.microsoft.com/en-us/library/cc246018.aspx)
    * [User Principal Name (UPN)](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380525%28v=vs.85%29.aspx#user_principal_name)
* **AccessControlInformation**: Indicates the collection of instances of the custom **cNtfsAccessControlInformation** CIM class that implements the following properties:
    * **AccessControlType**: Indicates whether to `Allow` or `Deny` access to the target item. The default value is `Allow`.
    * **FileSystemRights**: Indicates the access rights to be granted to the principal. This property is required.
     Specify one or more values from the [System.Security.AccessControl.FileSystemRights](https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights%28v=vs.110%29.aspx) enumeration type.
     Multiple values can be specified by using an array of strings or a single comma-separated string.
    * **Inheritance**: Indicates the inheritance type of the permission entry (the "*Applies to*" option). This property is only applicable to directories. Valid values are:
        * `None`
        * `ThisFolderOnly`
        * `ThisFolderSubfoldersAndFiles` (the default value)
        * `ThisFolderAndSubfolders`
        * `ThisFolderAndFiles`
        * `SubfoldersAndFilesOnly`
        * `SubfoldersOnly`
        * `FilesOnly`
    * **NoPropagateInherit**: Indicates whether the permission entry is not propagated to child objects. This property is only applicable to directories.
     Set this property to `$true` to ensure that the "*Only apply these permissions to objects and/or containers within this container*" option is enabled. The default value is `$false`.

#### Notes

If the **Ensure** property is set to `Absent`, the **AccessControlInformation** property is ignored. All explicit permissions associated with the specified principal are removed.

If the **Ensure** property is set to `Present` and the **AccessControlInformation** property is not specified, the default permission entry will be used as the reference entry.
 Default values are:

| ItemType    | AccessControlType   | FileSystemRights   | Inheritance                    | NoPropagateInherit |
|-------------|---------------------|--------------------|--------------------------------|--------------------|
| `Directory` | `Allow`             | `ReadAndExecute`   | `ThisFolderSubfoldersAndFiles` | `$false`           |
| `File`      | `Allow`             | `ReadAndExecute`   | *n/a*                          | *n/a*              |

If you want to assign multiple permission entries for a particular principal, it is recommended to make sure they are not automatically combined into a single permission entry.
 In such cases the **Test-TargetResource** function will always return `$false` (i.e., the resource is not in the desired state), and permissions will be reapplied every time DSC consistency check is executed.

### cNtfsPermissionsInheritance

The **cNtfsPermissionsInheritance** DSC resource provides a mechanism to manage NTFS permissions inheritance.

* **Path**: Indicates the path to the target item.
* **Enabled**: Indicates whether NTFS permissions inheritance is enabled. Set this property to `$false` to ensure it is disabled. The default value is `$true`.
* **PreserveInherited**: Indicates whether to preserve inherited permissions. Set this property to `$true` to convert inherited permissions into explicit permissions.
 The default value is `$false`. This property is ignored if **Enabled** is set to `$true`.

## Versions

### Unreleased

* The **cNtfsPermissionsInheritance** resource was added.
* Integration and unit tests were added.
* General improvements.

### 1.1.1 (October 15, 2015)

* Minor update.

### 1.1.0 (September 30, 2015)

* The **PermissionEntry** property was renamed to **AccessControlInformation**.

### 1.0.0 (September 29, 2015)

* Initial release with the following resources:
  * **cNtfsPermissionEntry**

## Examples

### Assign NTFS permissions

This example shows how to use the **cNtfsPermissionEntry** DSC resource to assign NTFS permissions.

```powershell

Configuration Sample_cNtfsPermissionEntry
{
    Import-DscResource -ModuleName cNtfsAccessControl
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $TestDirectoryPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'TestDirectory'

    File TestDirectory
    {
        Ensure = 'Present'
        DestinationPath = $TestDirectoryPath
        Type = 'Directory'
    }

    # Create a single permission entry for the local 'BUILTIN\Users' group.
    cNtfsPermissionEntry PermissionEntry1
    {
        Ensure = 'Present'
        Path = $TestDirectoryPath
        Principal = 'BUILTIN\Users'
        AccessControlInformation = @(
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = 'ThisFolderSubfoldersAndFiles'
                NoPropagateInherit = $false
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # Create multiple permission entries for the 'BUILTIN\Administrators' group.
    cNtfsPermissionEntry PermissionEntry2
    {
        Ensure = 'Present'
        Path = $TestDirectoryPath
        Principal = 'BUILTIN\Administrators'
        AccessControlInformation = @(
            cNtfsAccessControlInformation
            {
                FileSystemRights = 'Modify'
                Inheritance = 'ThisFolderOnly'
            }
            cNtfsAccessControlInformation
            {
                FileSystemRights = 'ReadAndExecute'
                Inheritance = 'ThisFolderSubfoldersAndFiles'
            }
            cNtfsAccessControlInformation
            {
                FileSystemRights = 'AppendData', 'CreateFiles'
                Inheritance = 'SubfoldersAndFilesOnly'
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # Remove all explicit permissions for the 'NT AUTHORITY\Authenticated Users' group.
    cNtfsPermissionEntry PermissionEntry3
    {
        Ensure = 'Absent'
        Path = $TestDirectoryPath
        Principal = 'NT AUTHORITY\Authenticated Users'
        DependsOn = '[File]TestDirectory'
    }
}

$OutputPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'Sample_cNtfsPermissionEntry'
Sample_cNtfsPermissionEntry -OutputPath $OutputPath
Start-DscConfiguration -Path $OutputPath -Force -Verbose -Wait
Get-DscConfiguration

```

### Disable NTFS permissions inheritance

This example shows how to use the **cNtfsPermissionsInheritance** DSC resource to disable NTFS permissions inheritance.

```powershell

Configuration Sample_cNtfsPermissionsInheritance
{
    Import-DscResource -ModuleName cNtfsAccessControl
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $TestDirectoryPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'TestDirectory'

    File TestDirectory
    {
        Ensure = 'Present'
        DestinationPath = $TestDirectoryPath
        Type = 'Directory'
    }

    # Disable permissions inheritance.
    cNtfsPermissionsInheritance DisableInheritance
    {
        Path = $TestDirectoryPath
        Enabled = $false
        PreserveInherited = $true
        DependsOn = '[File]TestDirectory'
    }
}

$OutputPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'Sample_cNtfsPermissionsInheritance'
Sample_cNtfsPermissionsInheritance -OutputPath $OutputPath
Start-DscConfiguration -Path $OutputPath -Force -Verbose -Wait
Get-DscConfiguration

```
