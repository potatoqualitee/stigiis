function Set-StgSessionStateInProc {
    <#
    .SYNOPSIS
        Configure and verify Session State Mode settings for vulnerability 76775 & 76813.

    .DESCRIPTION
        Configure and verify Session State Mode settings for vulnerability 76775 & 76813.

        Communication between a client and the web server is done using the HTTP protocol, but HTTP is a stateless protocol. In order to maintain a connection or session, a web server will generate a session identifier (ID) for each client session when the session is initiated. The session ID allows the web server to track a user session and, in many cases, the user, if the user previously logged into a hosted application. By being able to guess session IDs, an attacker can easily perform a man-in-the-middle attack. To truly generate random session identifiers that cannot be reproduced, the web server session ID generator, when used twice with the same input criteria, must generate an unrelated random ID. The session ID generator also needs to be a FIPS 140-2-approved generator.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76775, V-76813
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Set-StgSessionStateInProc -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgSessionStateInProc -ComputerName web01 -Credential ad\webadmin

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
            $webnames = (Get-Website).Name
            $filterpath = "system.web/sessionState"
            $preconfigMode = Get-WebConfigurationProperty -Filter $filterpath -Name Mode
            Set-WebConfigurationProperty -Filter $filterpath -Name Mode -Value "InProc"
            $postconfigurationMode = Get-WebConfigurationProperty -Filter $filterpath -Name Mode

            if ($postconfigurationMode -eq "InProc") {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id           = "V-76775"
                ComputerName = $env:COMPUTERNAME
                SiteName     = $env:COMPUTERNAME
                Before       = $preconfigMode
                After        = $postconfigurationMode
                Compliant    = $compliant
            }

            foreach ($webname in $webnames) {
                $preconfigMode = Get-WebConfigurationProperty -Filter $filterpath -Name Mode
                Set-WebConfigurationProperty -Filter $filterpath -Name Mode -Value "InProc"
                $postconfigurationMode = Get-WebConfigurationProperty -Filter $filterpath -Name Mode

                if ($postconfigurationMode -eq "InProc") {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id           = "V-76813"
                    ComputerName = $env:COMPUTERNAME
                    SiteName     = $webname
                    Before       = $preconfigMode
                    After        = $postconfigurationMode
                    Compliant    = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, Before, After, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

