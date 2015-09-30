# cNtfsAccessControl

The **cNtfsAccessControl** module contains the **cNtfsPermissionEntry** DSC resource that provides a mechanism to manage NTFS permission entries.

## Resources

### cNtfsPermissionEntry

* **Ensure**: Indicates if the permission entry exists. The default value is `Present`. Set this property to `Absent` to ensure that any explicit access rights the principal has are revoked.
* **Path**: Indicates the path to the target item.
* **ItemType**: Indicates whether the target item is a `Directory` or a `File`.
* **Principal**: Indicates the identity of the principal. Valid name formats: Down-Level Logon Name; User Principal Name; sAMAccountName; Security Identifier.
* **AccessControlInformation**: Indicates the collection of instances of the custom **cNtfsAccessControlInformation** CIM class that implements the following properties:
  * **AccessControlType**: Indicates whether to allow or deny access to the target item.
  * **FileSystemRights**: Indicates the access rights to be granted to the principal. Specify one or more values from the [System.Security.AccessControl.FileSystemRights](https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights%28v=vs.110%29.aspx) enumeration type. Multiple values can be specified by using a comma-separated string.
  * **Inheritance**: Apply to. This property is only valid when the **ItemType** property is set to `Directory`.
    Valid values:
    - `None`
    - `ThisFolderOnly`
    - `ThisFolderSubfoldersAndFiles`
    - `ThisFolderAndSubfolders`
    - `ThisFolderAndFiles`
    - `SubfoldersAndFilesOnly`
    - `SubfoldersOnly`
    - `FilesOnly`
  * **NoPropagateInherit**: Only apply these permissions to objects and/or containers within this container. This property is only valid when the **ItemType** property is set to `Directory`.

> **Note:**
> If the **Ensure** property is set to `Present` and the **AccessControlInformation** property is not specified, the default permission entry will be used as the reference entry.
Default permission entry: "Allow | Read & Execute | This folder, subfolders and files (Directory) / None (File)".

> **Note:**
> If the **Ensure** property is set to `Absent`, the **AccessControlInformation** property will be ignored.

> **Note:**
> If you want to assign multiple permission entries for a principal, it is strongly recommended to test them in advance to make sure they are not merging.
In such cases the **Test-TargetResource** function will always return `$false` (i.e. resource is not in the desired state), and permissions will be reapplied every time DSC Consistency Check is executed.

## Versions

### 1.1.0 (September 30, 2015)

* The **PermissionEntry** property was renamed to **AccessControlInformation**.

### 1.0.0 (September 29, 2015)

* Initial release with the following resources:
  - **cNtfsPermissionEntry**

## Examples

This configuration will create a directory and a file, and assign NTFS permissions on them.

```powershell

configuration Sample_cNtfsPermissionEntry
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName cNtfsAccessControl

    File TestDirectory
    {
        Ensure = 'Present'
        DestinationPath = 'C:\TestDirectory'
        Type = 'Directory'
    }

    File TestFile
    {
        Ensure = 'Present'
        DestinationPath = 'C:\TestDirectory\TestFile.txt'
        Type = 'File'
        Contents = ''
        DependsOn = '[File]TestDirectory'
    }

    # EXAMPLE 1: Add a single permission entry for a principal.
    # NOTE: If you do not specify the AccessControlInformation property, the default permission entry will be used as the reference entry.
    cNtfsPermissionEntry PermissionEntry1
    {
        Ensure = 'Present'
        Path = 'C:\TestDirectory'
        ItemType = 'Directory'
        Principal = $Env:UserDomain, $Env:UserName -join '\'
        DependsOn = '[File]TestDirectory'
    }

    # EXAMPLE 2: Add a single permission for a principal.
    cNtfsPermissionEntry PermissionEntry2
    {
        Ensure = 'Present'
        Path = 'C:\TestDirectory\TestFile.txt'
        ItemType = 'File'
        Principal = 'BUILTIN\Users'
        AccessControlInformation =
        @(
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'Modify'
            }
        )
        DependsOn = '[File]TestFile'
    }

    # EXAMPLE 3: Add multiple permission entries for a principal.
    cNtfsPermissionEntry PermissionEntry3
    {
        Ensure = 'Present'
        Path = 'C:\TestDirectory'
        ItemType = 'Directory'
        Principal = 'BUILTIN\Administrators'
        AccessControlInformation =
        @(
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'Modify'
                Inheritance = 'ThisFolderOnly'
                NoPropagateInherit = $false
            }
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = 'ThisFolderSubfoldersAndFiles'
                NoPropagateInherit = $false
            }
            cNtfsAccessControlInformation
            {
                AccessControlType = 'Allow'
                FileSystemRights = 'AppendData', 'CreateFiles'
                Inheritance = 'SubfoldersAndFilesOnly'
                NoPropagateInherit = $false
            }
        )
        DependsOn = '[File]TestDirectory'
    }

    # EXAMPLE 4: Remove all of the non-inherited permission entries for a principal.
    # NOTE: In case the AccessControlInformation property is specified, it will be ignored.
    cNtfsPermissionEntry PermissionEntry4
    {
        Ensure = 'Absent'
        Path = 'C:\TestDirectory'
        ItemType = 'Directory'
        Principal = 'BUILTIN\Users'
        DependsOn = '[File]TestDirectory'
    }

}

Sample_cNtfsPermissionEntry -OutputPath $Env:Temp

Start-DscConfiguration -Path $Env:Temp -Force -Verbose -Wait

Get-DscConfiguration


```

