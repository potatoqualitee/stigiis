function Get-StgLogSetting {
<#
    .SYNOPSIS
        Check, configure, and verify baseline logging setting for vulnerability 76683 & 76785.

    .DESCRIPTION
        Check, configure, and verify baseline logging setting for vulnerability 76683 & 76785.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76683, V-76785
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
        $scriptblock = {
            $WebPath = "MACHINE/WEBROOT/APPHOST"
            $filterpath = "system.applicationHost/sites/sitedefaults/logfile"
            $LogTarget = "logTargetW3C"
            $LogValues = "File,ETW"

            #Get pre-configuration values
            $PreWeb = Get-WebConfigurationProperty -PSPath $WebPath -Filter $filterpath -Name $LogTarget
            $PreWeb = $PreWeb.Split(",")

            #Output which radio buttons are set
            $PreWeb = @(

                if ($PreWeb -notcontains "ETW") {

                    "Log File Only"
                }

                elseif ($PreWeb -notcontains "File") {

                    "ETW Event Only"
                }

                else {

                    "Both log file and ETW Event"
                }
            )

            #Set Logging options to log file and ETW events (both)
            Set-WebConfigurationProperty -PSPath $WebPath -Filter $filterpath -Name $LogTarget -Value $LogValues

            Start-Sleep -Seconds 2
            #Get pre-configuration values
            $PostWeb = Get-WebConfigurationProperty -PSPath $WebPath -Filter $filterpath -Name $LogTarget
            $PostWeb = $PostWeb.Split(",")

            #Output which radio buttons are set
            $PostWeb = @(

                if ($PostWeb -notcontains "ETW") {

                    "Log File Only"
                }

                elseif ($PostWeb -notcontains "File") {

                    "ETW Event Only"
                }

                else {

                    "Both log file and ETW Event"
                }
            )

            [pscustomobject] @{

                Vulnerability = "V-76683, V-76785"
                PreConfig = "$PreWeb"
                PostConfiguration = "$PostWeb"
                Compliant = if ($PostWeb -eq "Both log file and ETW Event") {

                    "Yes"
                }

                else {

                    "No"
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property ComputerName, Id, Sitename, Hostname, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}