<#
Module manifest for the cNtfsAccessControl module.
#>

@{

# Version number of this module.
ModuleVersion = '1.2.0'

# ID used to uniquely identify this module
GUID = '8c4ba730-7d8e-4522-8c7e-a1b45108594c'

# Author of this module
Author = 'Serge Nikalaichyk'

# Copyright statement for this module
Copyright = '(c) 2015 Serge Nikalaichyk. All rights reserved.'

# Description of the functionality provided by this module
Description = 'The cNtfsAccessControl module contains DSC Resources for NTFS Access Control Management.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '4.0'

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('AccessControl', 'DSC', 'DesiredStateConfiguration', 'FileSystem', 'NTFS', 'PSModule')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/SNikalaichyk/cNtfsAccessControl/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/SNikalaichyk/cNtfsAccessControl'

    }

}

}

