function Get-StgLogDataField {
    <#
    .SYNOPSIS
        Add STIG required data fields to the logging feature, including currently active fields for vulnerability 76681 & 76783.

    .DESCRIPTION
        Add STIG required data fields to the logging feature, including currently active fields for vulnerability 76681 & 76783.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76681, V-76783
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgLogDataField -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgLogDataField -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and reports the necessary information
#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [PSFComputer[]]$ComputerName,
        [PSCredential]$Credential,
        [string[]]$webnames = (Get-Website).Name,
        [switch]$EnableException
    )
    begin {
        . "$script:ModuleRoot\private\Set-Defaults.ps1"
        $scriptblock = {
            #All fields presented after new properties have been set
            $postFields = (Get-WebConfiguration -Filter System.Applicationhost/Sites/SiteDefaults/logfile).LogExtFileFlags.Split(",")

            if ($postFields -contains "Date" -and $postFields -contains "Time" -and $postFields -contains "ClientIP" -and $postFields -contains "UserName" -and $postFields -contains "Method" -and $postFields -contains "UriQuery" -and $postFields -contains "HTTPstatus" -and $postFields -contains "Referer") {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id                      = "V-76681", "V-76783"
                ComputerName            = $env:COMPUTERNAME
                Date                    = ($postFields -contains "Date")
                Time                    = ($postFields -contains "Time")
                ClientIP                = ($postFields -contains "ClientIP")
                UserName                = ($postFields -contains "UserName")
                Method                  = ($postFields -contains "Method")
                URIQuery                = ($postFields -contains "UriQuery")
                ProtocolStatus          = ($postFields -contains "HTTPstatus")
                Referer                 = ($postFields -contains "Referer")
                Fields                  = $postFields
                Compliant               = $compliant
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Date, Time, ClientIP, UserName, Method, URIQuery, ProtocolStatus, Fields, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
