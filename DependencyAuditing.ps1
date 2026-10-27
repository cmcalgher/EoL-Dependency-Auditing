# USAGE:
#
# To collect relevant dependency auditing events from the security event log and export them to a CSV:
#
# .\DependencyAuditing.ps1 -Action GetAuditing
#
# To set auditing on the files found under each row's 'basepaths' that match its 'filterstring':
#
# .\DependencyAuditing.ps1 -Action SetAuditing
#
# To preview which files SetAuditing would change, without changing anything:
#
# .\DependencyAuditing.ps1 -Action SetAuditing -WhatIf
#
# The CSV is read from, and the event export is written to, the same folder this script is saved in.
#
# Both actions read from ONE CSV file (default: Dependencies.csv next to this script) with these columns:
#
#   name         - friendly name of the dependency (used to label collected events and console output)
#   string       - regex matched (case-insensitive) against the ObjectName of 4663 events   (GetAuditing)
#   basepaths    - one or more folders to scan recursively, separated by commas,
#                  e.g. "c:\windows\system32, c:\windows\SysWOW64"                         (SetAuditing)
#   filterstring - regex matched (case-insensitive) against the full path of files under basepaths (SetAuditing)
#
# Rows with a blank 'string' are skipped by GetAuditing, and rows with a blank 'basepaths' are skipped by SetAuditing.



[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet('GetAuditing', 'SetAuditing')]
    [string]$Action,

    # Defaults to Dependencies.csv in the same folder as this script.
    [string]$CsvPath
)

# The folder this script is saved in. Both the input CSV and the exported event CSV live here.

$ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptDir)) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    $CsvPath = Join-Path $ScriptDir 'Dependencies.csv'
}

$ExportPath = Join-Path $ScriptDir "$($env:COMPUTERNAME)_AuditEventData.csv"

# Imports the single CSV file that drives both event collection and setting the auditing ACL's.

$DependencyData = Import-Csv $CsvPath

# The below function is what collects the events, specifically event ID 4663 events, from the last 24 hours.
# Depending on the volume of 4663 events, this part MAY time-out. This can happen for things like web page files that are touched by web app
# exe's, which depending on how many use it, may need to have the auditing side of the ACL's disabled.
function Get-DependencyEvents {

    # Only rows that have a search string are used for event matching.
    $dependencyInfo = $DependencyData | Where-Object { -not [string]::IsNullOrWhiteSpace($_.string) }

    # This next line sets the 'in the last x number of hours' limit for event collection.

    $StartTime = (Get-Date).AddHours(-24)
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$StartTime; Id='4663'}

    # Parse every event's XML once, up front, rather than once per dependency.

    $parsedEvents = $events | ForEach-Object {
        $xml = ([xml]$_.ToXml()).Event.EventData.Data
        [PSCustomObject]@{
            ProcessName = ($xml | Where-Object {$_.Name -eq "ProcessName"}).'#text'
            ObjectName  = ($xml | Where-Object {$_.Name -eq "ObjectName"}).'#text'
            EventTime   = $_.TimeCreated
        }
    }

    # The below loops through each dependency row, collecting matching events,
    # and appends them to a CSV. That CSV is named based on the host name the script is ran on, as well.

    foreach ($dependency in $dependencyInfo){
        $parsedEvents | Where-Object {$_.ObjectName -imatch $dependency.string} |
            ForEach-Object {
                [PSCustomObject]@{
                    HostName    = $env:COMPUTERNAME
                    Dependency  = $dependency.name
                    ProcessName = $_.ProcessName
                    ObjectName  = $_.ObjectName
                    EventTime   = $_.EventTime
                }
            } |
            Export-Csv -NoTypeInformation -Path $ExportPath -Append -WhatIf:$false
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

    $existingAcl = Get-Acl -Path $file -Audit
    $existingAcl.AddAuditRule($auditRule) | Out-Null
    Set-Acl -Path $file -AclObject $existingAcl
}

# the below function leverages the previous two functions to set the ACL's on files under each row's 'basepaths'
# that match that row's 'filterstring'.
function Enable-DependencyEvents {

    $newAuditRule = Get-AuditRuleForFile

    # Split each row's 'basepaths' cell into individual folders, and build one list of unique folder + filter pairs.
    # Several rows share the same folders and filter (e.g. all the DotNet rows), so each pair is only scanned once,
    # with the dependency names that share it kept together for the console output.

    $scanList = @{}

    foreach ($dependency in $DependencyData){
        if ([string]::IsNullOrWhiteSpace($dependency.basepaths)) { continue }

        $paths = $dependency.basepaths -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne '' }

        foreach ($path in $paths){
            $key = "$($path.ToLower())|$($dependency.filterstring)"
            if (-not $scanList.ContainsKey($key)) {
                $scanList[$key] = [PSCustomObject]@{
                    Path         = $path
                    FilterString = $dependency.filterstring
                    Names        = New-Object System.Collections.Generic.List[string]
                }
            }
            $scanList[$key].Names.Add($dependency.name)
        }
    }

# below foreach loop iterates through each unique folder + filter pair, and ADDS the required auditing-side ACL settings.

    foreach ($scan in $scanList.Values){
        $names = $scan.Names -join ', '
        Write-Host "[$($names)] checking path $($scan.Path) for DLLs to set Auditing on..."

        if (-not (Test-Path -Path $scan.Path)) {
            Write-Host "    path not found, skipping."
            continue
        }

        Get-ChildItem -Path $scan.Path -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object FullName -IMatch $scan.FilterString |
            ForEach-Object {
                Write-Host "Setting auditing on $($_.FullName)..."
                Set-FileAuditRule $_.FullName $newAuditRule
            }
    }
}

# switch used to determine which action to take with this script (either to set the auditing settings of files, or collect events)

switch ($Action){
    "GetAuditing" {Get-DependencyEvents}
    "SetAuditing" {Enable-DependencyEvents}
}
