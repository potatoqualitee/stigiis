function Get-StgGroupMembership {
    <#
    .SYNOPSIS
        Check baseline account/security group accesses for vulnerability 76707 & 76719.

    .DESCRIPTION
        Check baseline account/security group accesses for vulnerability 76707 & 76719.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76707, V-76719
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgAltHostname -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgAltHostname -ComputerName web01 -Credential ad\webadmin

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
            #Get Local administrators and groups
            $LocalGroups = net localgroup | where {$_ -notmatch "command completed successfully" -or $_ -notmatch ""} | select -Skip 6 | ForEach-Object {$_.Replace("*", "")}
            $LocalAdmin = net localgroup Administrators | where {$_ -notmatch "command completed successfully"} | select -Skip 6

            foreach ($LA in $LocalAdmin) {
                if (-not ([string]::IsNullOrWhiteSpace($LA))) {
                    [pscustomobject] @{
                        Id                = "V-76707", "V-76719"
                        ComputerName      = $env:COMPUTERNAME
                        AccessType        = "Local Administrator"
                        User              = $LA
                        SecurityGroup     = ""
                        ObjectClass       = ""
                        DistinguishedName = "N/A"
                    }
                }
            }

            foreach ($LG in $LocalGroups) {
                if ($LG) {
                    try {
                        #Get group members of Security Groups
                        $Members = Get-ADGroupMember $LG -ErrorAction Stop
                    } catch {
                        $Members = @()
                    }

                    foreach ($Member in $Members) {
                        if ($Member) {
                            [pscustomobject] @{
                                Id                = "V-76707", "V-76719"
                                ComputerName      = $env:COMPUTERNAME
                                AccessType        = "Group Membership"
                                User              = $Member.SamAccountName
                                SecurityGroup     = $LG
                                ObjectClass       = $Member.objectClass.ToUpper()
                                DistinguishedName = $Member.DistinguishedName
                            }
                        }
                    }
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, AccessType, User, SecurityGroup, ObjectClass, DistinguishedName |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}