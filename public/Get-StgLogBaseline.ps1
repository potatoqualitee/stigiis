function Get-StgLogBaseline {
    <#
    .SYNOPSIS
        Check, configure, and verify baseline logging setting for vulnerability 76683 & 76787.

    .DESCRIPTION
        Check, configure, and verify baseline logging setting for vulnerability 76683 & 76787.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76685, V-76787
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
            $LogFilePath = "C:\inetpub\logs\LogFiles\W3SVC2"
            $WebIP = (Get-NetIPAddress | Where-Object { $_.InterfaceAlias -notlike "*Loopback*"}).IPAddress

            #Retrieve most recent log file
            $CurrentLog = Get-ChildItem $LogFilePath -Force | Sort-Object LastWriteTime -Descending | Select-Object -First 1

            #Parse log files for data
            $logtail = Get-Content -Path "$LogFilePath\$($CurrentLog.Name)" -Tail 200 -Force
            if ($WebIP -match $tail.Split(" ")[2]) {
                $compliant = $true
            } else {
                $compliant = $false
            }

            foreach ($tail in $logtail) {
                [pscustomobject] @{
                    Id           = "V-76685", "V-76787"
                    ComputerName = $env:COMPUTERNAME
                    Date         = $tail.Split(" ")[0]
                    Time         = $tail.Split(" ")[1]
                    WebServerIP  = $WebIP
                    SourceIP     = $tail.Split(" ")[2]
                    Method       = $tail.Split(" ")[3]
                    URIStem      = $tail.Split(" ")[4]
                    URIQuery     = $tail.Split(" ")[5]
                    SourcePort   = $tail.Split(" ")[6]
                    UserName     = $tail.Split(" ")[7]
                    ClientIP     = $tail.Split(" ")[8]
                    UserAgent    = $tail.Split(" ")[9]
                    Referer      = $tail.Split(" ")[10]
                    HTTPstatus   = $tail.Split(" ")[11]
                    HTTPSstatus  = $tail.Split(" ")[12]
                    Win32Status  = $tail.Split(" ")[13]
                    TimeTaken    = $tail.Split(" ")[14]
                    Compliant    = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Date, Time, WebServerIP, SourceIP, Method, URIStem, URIQuery, SourcePort, UserName, ClientIP, UserAgent, Referer, HTTPStatus, HTTPSStatus, Win32Status, TimeTaken, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}