#region License
    # Copyright 2017 University of Minnesota, Office of Information Technology

    # This program is free software: you can redistribute it and/or modify
    # it under the terms of the GNU General Public License as published by
    # the Free Software Foundation, either version 3 of the License, or
    # (at your option) any later version.

    # This program is distributed in the hope that it will be useful,
    # but WITHOUT ANY WARRANTY; without even the implied warranty of
    # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    # GNU General Public License for more details.

    # You should have received a copy of the GNU General Public License
    # along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
#endregion
#
# Module manifest for module 'UMN-Grouper'
#
# Generated by: Travis Sobeck
#
# Generated on: 7/30/2018
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'UMN-Grouper.psm1'

# Version number of this module.
ModuleVersion = '1.0.12'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '959478c8-e519-43be-b1f6-a104e3529293'

# Author of this module
Author = 'Travis Sobeck'

# Company or vendor of this module
CompanyName = 'University of Minnesota'

# Copyright statement for this module
Copyright = '(c) 2016 Regents of the University of Minnesota. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Powershell wrappers for interacting with Grouper Rest API'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
#FunctionsToExport = '*'
FunctionsToExport = @("Set-GrouperPrivileges","Set-GrouperGroupAttributeAssignments","Remove-GrouperStem","Remove-GrouperGroupMember","remove-GrouperGroupAttributeAssignments","Remove-GrouperGroup","New-GrouperStem","New-GrouperHeader","New-GrouperGroupMember","New-GrouperGroup","Get-GrouperStemByUUID","Get-GrouperStemByParent","Get-GrouperStem","Get-GrouperPrivileges","Get-GrouperGroupsForMember","Get-GrouperGroupMembers","get-grouperGroupAttributeAssignments","Get-GrouperGroup","Get-GrouperAttributeDefNames"
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = '*'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/umn-microsoft-automation/UMN-Grouper'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = "Updated variable text from New-Header to New-GrouperHeader"

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}
