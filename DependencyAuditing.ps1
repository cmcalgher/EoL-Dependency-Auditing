# USAGE:
#
# To collect relevant dependency auditing events from the security event log and export them to a CSV:
#
# .\DependencyAuditing.ps1 -Action GetAuditing
#
# To set the auditing on files specified in the 'DependencyPaths.csv':
#
# .\DependencyAuditing.ps1 -Action SetAuditing



[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Action
)

# Imports the CSV file, which includes needed search strings, to determine what files to search events for, or set auditing ACL's on.

$DependencyInfo = Import-CSV "c:\temp\Dependencies.csv"

# The below function is what collects the events, specifically event ID 4663 events, from the last 24 hours.
# Depending on the volume of 4663 events, this part MAY time-out. This can happen for things like web page files that are touched by web app
# exe's, which depending on how many use it, may need to have the auditing side of the ACL's disabled.
function Get-DependencyEvents {

    # This next line sets the 'in the last x number of hours' limit for event collection.

    $StartTime = (Get-Date).AddHours(-24)
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$StartTime; Id='4663'}

    # The below takes the information in one of the columns in the previously imported CSV, and loops through each line, collecting matching events, 
    # and appends them to a CSV. That CSV is named based on the host name the script is ran on, as well.

    foreach ($dependency in $dependencyInfo){

        $parsedEvents = $events |  foreach-object {$xml = ([xml]$_.ToXml()).Event.EventData.Data
            [PSCustomObject]@{
                HostName = $env:COMPUTERNAME
                Dependency = $dependency.Name
                ProcessName = ($xml | where {$_.Name -eq "ProcessName"}).'#text'
                ObjectName = ($xml | where {$_.Name -eq "ObjectName"}).'#text'
                EventTime = $_.TimeCreated
            }
        }
        $parsedEvents | where {$_.ObjectName -imatch $dependency.string} | 
            Export-Csv -NoTypeInformation -Path "c:\temp\$(hostname)_AuditEventData.csv" -Append
    }

}

# the below function is used to store the needed auditing-side of the ACL settings that are set to enable the 4663 events on individual files.
function Get-AuditRuleForFile {
    $auditRuleArguments =   'Everyone'              <# identity #>,
                            'ExecuteFile, Traverse' <# fileSystemRights #>,
                            'Success'               <# flags #>
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule($auditRuleArguments)

return $auditRule
}

# the below function grabs the CURRENT settings of the auditing-side of a file's ACL, and adds the settings required for generating 4663 events.
function Set-FileAuditRule {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$file,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.AccessControl.FileSystemAuditRule]$auditRule
    )

$existingAcl = Get-Acl -Path $file
    $existingAcl.AddAuditRule($auditRule) | Out-Null
    Set-Acl -Path $file -AclObject $existingAcl
}

# the below function leverages the previous two functions to set the ACL's on files matching the strings found in the 'DependencyPaths.csv' file.
function Enable-DependencyEvents {

    $DependencyPaths = Import-CSV "C:\temp\DependencyPaths.csv"
    $newAuditRule = Get-AuditRuleForFile

# below foreach loop iterates through each line in the 'DependencyPaths.csv' file, and ADDS the required auditing-side ACL settings.

    foreach ($dependencyPath in $DependencyPaths){
        $path = $dependencyPath.basepath
        $filterString = $dependencyPath.filterstring
        write-host "checking path $($path) for DLLs to set Auditing on..."
        Get-ChildItem $path -ErrorAction SilentlyContinue -Recurse |
        Where-Object FullName -IMatch $filterString |
            ForEach-Object {
                write-host "Setting auditing on $($_.FullName)..."
                Set-FileAuditRule $_.FullName $newAuditRule
            }
        }
}

# switch used to determine which action to take with this script (either to set the auditing settings of files, or collect events)

switch ($Action){
    "GetAuditing" {Get-DependencyEvents}
    "SetAuditing" {Enable-DependencyEvents}
}

