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
    }
    process {
        Write-PSFMessage -Level Verbose -Message "Reporting STIG Settings for $($MyInvocation.MyCommand)"

        $WebPath = "MACHINE/WEBROOT/APPHOST"
        $LogDirectory = (Get-WebConfigurationProperty -PSPath $WebPath -Filter "system.applicationHost/sites/sitedefaults/logfile" -Name Directory).Value.Replace("%SystemDrive%","$env:SystemDrive")

        #Child directories of IIS log directory
        $LogDirectoryChildren = (Get-ChildItem -Path $LogDirectory -Directory -Recurse -Force)

        foreach($LDC in $LogDirectoryChildren) {
            #Get permissions for each user/security group
            $ACL = (Get-Acl -Path $LDC.FullName).Access

            foreach($Access in $ACL) {
                [pscustomobject] @{
                    Directory = $LDC.FullName
                    "User/Group" = $Access.IdentityReference
                    Permissions = $Access.FileSystemRights
                    Inherited = $Access.IsInherited
                }
            }
        }
    }
}
