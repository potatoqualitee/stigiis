function Get-StgV-76707-76719 {
<#
    .SYNOPSIS
        Check baseline account/security group accesses for vulnerability 76707 & 76719.

    .DESCRIPTION
        Check baseline account/security group accesses for vulnerability 76707 & 76719.

    .NOTES
        Tags: V-76707, V-76719
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    #Get Local administrators and groups
    $LocalGroups = net localgroup | where {$_ -notmatch "command completed successfully" -or $_ -notmatch ''} | select -Skip 6 | ForEach-Object {$_.Replace('*','')}
    $LocalAdmin = net localgroup Administrators | where {$_ -notmatch "command completed successfully"} | select -Skip 6

    foreach($LA in $LocalAdmin) {

        if(!([string]::IsNullOrWhiteSpace($LA))) {

            [pscustomobject] @{

                Vulnerability = "V-76707, V-76719"
                Computername = $env:COMPUTERNAME
                AccessType = 'Local Administrator'
                User = $LA
                SecurityGroup = ''
                ObjectClass = ''
                DistinguishedName = 'N/A'
            }
        }
    }

    foreach($LG in $LocalGroups) {

        if(!([string]::IsNullOrWhiteSpace($LG))) {

            try {

                #Get group members of Security Groups
                $Members = Get-ADGroupMember $LG -ErrorAction Stop
            }

            catch {

                $Members = @()
            }

            foreach($Member in $Members) {

                if(!([string]::IsNullOrWhiteSpace($Member))) {

                    [pscustomobject] @{

                        Vulnerability = "V-76707, V-76719"
                        Computername = $env:COMPUTERNAME
                        AccessType = 'Group Membership'
                        User = $Member.SamAccountName
                        SecurityGroup = $LG
                        ObjectClass = $Member.objectClass.ToUpper()
                        DistinguishedName = $Member.DistinguishedName
                    }
                }
            }
        }
    }

}
