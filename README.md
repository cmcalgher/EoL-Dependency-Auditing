# EoL-Dependency-Auditing
This PowerShell Script Outputs a .CSV that contains events showing usage of pre-specified EoL software dependencies, leveraging the the security event log on a machine, and configuring GPO/ACL audit settings on specific .DLL files.

This was inspired by the following, so a MASSIVE bunch of credit goes to whoever cooked this up initially:

https://learn.microsoft.com/en-us/cpp/windows/redist-version-auditing?view=msvc-170

Before using this, you will need to configure an Advanced Audit Policy setting, either via GPO or via Local Policy. Those specific settings can be found in the above article.

Currently, the list of EoL or dependencies that this tracks can be found in the CSV. This can be edited for additional dependencies, but you will need to have an idea of their exact paths, so you don't inadvertently adjust the auditing ACL on a ton of unnecessary items.

Additionally, prior to rolling this out to an entire environment, it is worth gauging the size increase of the security event log. Some files may already have the file level side of the auditing set, and enabling the GPO/Local policy setting may inadvertently blow up the security event logs.

The main script is used to either set the auditing ACL's on the file-level side, or collect relevant events pertaining to the items specified in the CSV. If collecting events, it will collect events from the past 24 hours, and export them to a CSV, neatly formatted, and able to be merged with other of the same files found across whatever environment you end up using this on.

So if you are not wanting to do 'scream tests' during vulnerability remediation, and have no idea if removing VC++ 2012 or that random .NET 5 installation will cause a critical business application to come crashing down, you can let this run for a while to get an idea if it is actually 'safe' to rip that EoL software out.

this powershell 'code' could probably be cleaned up a ton and/or optimized, but I am a humble IT professional who does vulnerability remediation, and wear what I call an 'aluminum crown' when approaching EoL software remediation.

