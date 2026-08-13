[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Action
)

$DependencyInfo = Import-CSV "c:\temp\Dependencies.csv"


function Get-DependencyEvents {

    $StartTime = (Get-Date).AddHours(-24)
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$StartTime; Id='4663'}

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

function Get-AuditRuleForFile {
    $auditRuleArguments =   'Everyone'              <# identity #>,
                            'ExecuteFile, Traverse' <# fileSystemRights #>,
                            'Success'               <# flags #>
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule($auditRuleArguments)

return $auditRule
}

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

function Enable-DependencyEvents {

    $DependencyPaths = Import-CSV "C:\temp\DependencyPaths.csv"
    $newAuditRule = Get-AuditRuleForFile


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

switch ($Action){
    "GetAuditing" {Get-DependencyEvents}
    "SetAuditing" {Enable-DependencyEvents}
}

