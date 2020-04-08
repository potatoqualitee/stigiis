function Get-StgLogDataField {
    <#
    .SYNOPSIS
        Add STIG required data fields to the logging feature, including currently active fields for vulnerability 76681 & 76783.

    .DESCRIPTION
        Add STIG required data fields to the logging feature, including currently active fields for vulnerability 76681 & 76783.

    .NOTES
        Tags: V-76681, V-76783
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT
#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [PSFComputer[]]$ComputerName,
        [PSCredential]$Credential,
        [string[]]$WebNames = (Get-Website).Name,
        [switch]$EnableException
    )
    begin {
        . "$script:ModuleRoot\private\Set-Defaults.ps1"
    }
    process {
        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        #STIG required log fields
        $RequiredFields = @(

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
        $CurrentFields = (Get-WebConfiguration -Filter System.Applicationhost/Sites/SiteDefaults/logfile).LogExtFileFlags.Split(",")

        #Combine STIG fields and current fields (to ensure nothing is turned off, only turned on)
        [String[]]$Collection = @(

            $RequiredFields
            $CurrentFields
        )

        $CollectionString = ($Collection | Select-Object -Unique)

        $Replace = $CollectionString.Replace(' ',",")

        #Set all necessary log fields
        Set-WebConfigurationProperty -Filter 'System.Applicationhost/Sites/SiteDefaults/logfile' -Name 'LogExtFileFlags' -Value $Replace

        #All fields presented after new properties have been set
        $PostFields = (Get-WebConfiguration -Filter System.Applicationhost/Sites/SiteDefaults/logfile).LogExtFileFlags.Split(",")

        [pscustomobject] @{

            Vulnerability = 'V-76681, V-76783'
            PreConfigFields = "$CurrentFields"
            Date = ($PostFields -contains "Date")
            Time = ($PostFields -contains "Time")
            ClientIP = ($PostFields -contains "ClientIP")
            UserName = ($PostFields -contains "UserName")
            Method = ($PostFields -contains "Method")
            URIQuery = ($PostFields -contains "UriQuery")
            ProtocolStatus = ($PostFields -contains "HTTPstatus")
            Referer = ($PostFields -contains "Referer")
            PostConfigurationFields = "$PostFields"
            Compliant = if ($PostFields -contains "Date" -and $PostFields -contains "Time" -and $PostFields -contains "ClientIP" -and $PostFields -contains "UserName" -and $PostFields -contains "Method" -and $PostFields -contains "UriQuery" -and $PostFields -contains "HTTPstatus" -and $PostFields -contains "Referer") {

                "Yes"
            }

            else {

                "No"
            }
        }
    }
}