function Set-StgLogSetting {
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

    .EXAMPLE
        PS C:\> Set-StgLogSetting -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgLogSetting -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and updates the necessary setting

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
            $filterpath = "system.applicationHost/sites/sitedefaults/logfile"
            Start-Process -FilePath "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList "unlock", "config", "-section:$filterpath" -Wait
            $logtarget = "logTargetW3C"
            $logvalues = "File,ETW"

            #Get pre-configuration values
            $preconfig = Get-WebConfigurationProperty -PSPath $webpath -Filter $filterpath -Name $logtarget
            $preconfig = $preconfig.Split(",")

            #Output which radio buttons are set
            $preconfig = @(
                if ($preconfig -notcontains "ETW") {
                    "Log File Only"
                } elseif ($preconfig -notcontains "File") {
                    "ETW Event Only"
                } else {
                    "Both log file and ETW Event"
                }
            )

            #Set Logging options to log file and ETW events (both)
            $null = Set-WebConfigurationProperty -PSPath $webpath -Filter $filterpath -Name $logtarget -Value $logvalues

            Start-Sleep -Seconds 2
            #Get pre-c                                                                 onfiguration values
            $postconfig = Get-WebConfigurationProperty -PSPath $webpath -Filter $filterpath -Name $logtarget
            $postconfig = $postconfig.Split(",")

            #Output which radio buttons are set
            $postconfig = @(
                if ($postconfig -notcontains "ETW") {
                    "Log File Only"
                } elseif ($postconfig -notcontains "File") {
                    "ETW Event Only"
                } else {
                    "Both log file and ETW Event"
                }
            )

            if ($postconfig -eq "Both log file and ETW Event") {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id        = "V-76683", "V-76785"
                Before    = $preconfig
                After     = $postconfig
                Compliant = $compliant
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Before, After, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

