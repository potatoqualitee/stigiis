function Set-StgLogDataField {
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
        PS C:\> Set-StgLogDataField -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgLogDataField -ComputerName web01 -Credential ad\webadmin

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
            #STIG required log fields
            $requiredfields = @(
                "Date",
                "Time",
                "ClientIP",
                "UserName",
                "Method",
                "UriQuery",
                "HttpStatus",
                "Referer"
            )

            #Current log fields
            $currentfields = (Get-WebConfiguration -Filter System.Applicationhost/Sites/SiteDefaults/logfile).LogExtFileFlags.Split(",")

            #Combine STIG fields and current fields (to ensure nothing is turned off, only turned on)
            [String[]]$collection = @(
                $requiredfields
                $currentfields
            )

            $collectionstring = ($collection | Select-Object -Unique)
            $replace = $collectionstring.Replace(" ", ",")

            #Set all necessary log fields
            $filterpath = "System.Applicationhost/Sites/SiteDefaults/logfile"
            Start-Process -FilePath "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList "unlock", "config", "-section:$filterpath" -Wait
            $null = Set-WebConfigurationProperty -Filter $filterpath -Name "LogExtFileFlags" -Value $replace

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
                PreConfigFields         = $currentfields
                Date                    = ($postFields -contains "Date")
                Time                    = ($postFields -contains "Time")
                ClientIP                = ($postFields -contains "ClientIP")
                UserName                = ($postFields -contains "UserName")
                Method                  = ($postFields -contains "Method")
                URIQuery                = ($postFields -contains "UriQuery")
                ProtocolStatus          = ($postFields -contains "HTTPstatus")
                Referer                 = ($postFields -contains "Referer")
                PostConfigFields        = $postFields
                Compliant               = $compliant
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Date, Time, ClientIP, UserName, Method, URIQuery, ProtocolStatus, PreConfigFields, PostConfigFields, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}