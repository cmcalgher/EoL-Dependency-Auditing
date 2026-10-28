# USAGE:
#
# To collect relevant dependency auditing events from the security event log and export them to a CSV:
#
# .\DependencyAuditing.ps1 -Action GetAuditing
#
# To search further back (or less far back) than the default 24 hours, add -Hours, e.g. the last 3 days:
#
# .\DependencyAuditing.ps1 -Action GetAuditing -Hours 72
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
    [string]$CsvPath,

    # GetAuditing only: how many hours back to search the Security event log for matching events. Defaults to 24.
    [ValidateRange(1, [int]::MaxValue)]
    [int]$Hours = 24
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

# The below function is what collects the events, specifically event ID 4663 events, from the last -Hours hours (default 24).
# Larger -Hours values pull in more events and take longer.
# Depending on the volume of 4663 events, this part MAY time-out. This can happen for things like web page files that are touched by web app
# exe's, which depending on how many use it, may need to have the auditing side of the ACL's disabled.
function Get-DependencyEvents {

    # Only rows that have a search string are used for event matching.
    $dependencyInfo = $DependencyData | Where-Object { -not [string]::IsNullOrWhiteSpace($_.string) }

    # This next line sets the 'in the last x number of hours' limit for event collection, from the -Hours parameter.

    $StartTime = (Get-Date).AddHours(-$Hours)
    Write-Host "Searching the Security event log for 4663 events from the last $($Hours) hour(s)..."
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

    # STEP 1: The below loops through each dependency row, collecting matching events,
    # and APPENDS them to the export CSV. That CSV is named based on the host name the script is ran on, as well.

    $appendedCount = 0
    foreach ($dependency in $dependencyInfo){
        $matched = @($parsedEvents | Where-Object {$_.ObjectName -imatch $dependency.string} |
            ForEach-Object {
                [PSCustomObject]@{
                    HostName    = $env:COMPUTERNAME
                    Dependency  = $dependency.name
                    ProcessName = $_.ProcessName
                    ObjectName  = $_.ObjectName
                    EventTime   = $_.EventTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            })

        if ($matched.Count -gt 0) {
            $matched | Export-Csv -NoTypeInformation -Path $ExportPath -Append -WhatIf:$false
            $appendedCount += $matched.Count
        }
    }
    Write-Host "Appended $($appendedCount) matching events to $($ExportPath)"

    # STEP 2: De-duplicate the whole export file (rows from this run AND all previous runs).

    Remove-DuplicateDependencyEvents
}

# Reads the full export file back in, keeps only the most recent entry for each unique
# Dependency + ProcessName + ObjectName combination, and rewrites the file with just those rows.
function Remove-DuplicateDependencyEvents {

    if (-not (Test-Path -Path $ExportPath)) {
        Write-Host "No export file found at $($ExportPath), nothing to de-duplicate."
        return
    }

    $allRows = @(Import-Csv -Path $ExportPath)

    $latestRows = @($allRows |
        Group-Object -Property Dependency, ProcessName, ObjectName |
        ForEach-Object {
            $_.Group |
                Sort-Object -Property @{ Expression = { ConvertTo-EventDateTime $_.EventTime } } -Descending |
                Select-Object -First 1
        } |
        Sort-Object -Property Dependency, ProcessName, ObjectName |
        Select-Object HostName, Dependency, ProcessName, ObjectName,
            @{Name = 'EventTime'; Expression = { (ConvertTo-EventDateTime $_.EventTime).ToString('yyyy-MM-dd HH:mm:ss') }})

    if ($latestRows.Count -gt 0) {
        $latestRows | Export-Csv -NoTypeInformation -Path $ExportPath -WhatIf:$false
    }
    Write-Host "De-duplicated $($ExportPath): $($allRows.Count) rows reduced to $($latestRows.Count) unique entries."
}

# Converts an EventTime value read back from the export CSV into a real date, so events can be compared by time.
# Handles both the format this script now writes (yyyy-MM-dd HH:mm:ss) and the local date format older runs wrote.
function ConvertTo-EventDateTime {
    param ([string]$value)

    $parsed = [datetime]::MinValue
    if ([datetime]::TryParseExact($value, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        return $parsed
    }
    if ([datetime]::TryParse($value, [ref]$parsed)) {
        return $parsed
    }
    return [datetime]::MinValue
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
