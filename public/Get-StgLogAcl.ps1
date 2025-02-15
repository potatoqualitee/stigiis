function Get-StgLogAcl {
<#
    .SYNOPSIS
        Report log file ACL settings for vulnerabilities 76695, 76697, & 76795. Needs to be assessed manually.

    .DESCRIPTION
        Report log file ACL settings for vulnerabilities 76695, 76697, & 76795. Needs to be assessed manually.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76695, V-76697, V-76795, Documentation
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgLogAcl -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgLogAcl -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and reports the necessary information
#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [PSFComputer[]]$ComputerName,
        [PSCredential]$Credential,
        [switch]$EnableException
    )
    begin {
        . "$script:ModuleRoot\private\Set-Defaults.ps1"
        $scriptblock = {
            $webpath = "MACHINE/WEBROOT/APPHOST"
            $logdirectory = (Get-WebConfigurationProperty -PSPath $webpath -Filter "system.applicationHost/sites/sitedefaults/logfile" -Name Directory).Value.Replace("%SystemDrive%",$env:SystemDrive)

            #Child directories of IIS log directory
            $files = (Get-ChildItem -Path $logdirectory -Directory -Recurse -Force)

            foreach($file in $files) {
                #Get permissions for each user/security group
                $acl = (Get-Acl -Path $file.FullName).Access

                foreach($access in $acl) {
                    [pscustomobject] @{
                        Id           = "V-76695", "V-76697", "V-76795"
                        ComputerName = $env:COMPUTERNAME
                        Directory    = $file.FullName
                        Account      = $access.IdentityReference
                        Permissions  = $access.FileSystemRights
                        Inherited    = $access.IsInherited
                    }
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Directory, Account, Permissions, Inherited |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
