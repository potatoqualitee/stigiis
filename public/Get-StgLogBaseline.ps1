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
        $LogFilePath = 'C:\inetpub\logs\LogFiles\W3SVC2'
        $WebIP = (Get-NetIPAddress | Where-Object { $_.InterfaceAlias -notlike "*Loopback*"}).IPAddress


        #Retrieve most recent log file
        $CurrentLog = Get-ChildItem $LogFilePath -Force | Sort-Object LastWriteTime -Descending | Select-Object -First 1

        #Parse log files for data
        $LogTail = Get-Content -Path "$LogFilePath\$($CurrentLog.Name)" -Tail 200 -Force

        foreach($Tail in $LogTail) {

            [pscustomobject] @{

                Date = $Tail.Split(' ')[0]
                Time = $Tail.Split(' ')[1]
                WebServerIP = $WebIP
                SourceIP = $Tail.Split(' ')[2]
                Method = $Tail.Split(' ')[3]
                URIStem =$Tail.Split(' ')[4]
                URIQuery = $Tail.Split(' ')[5]
                SourcePort =$Tail.Split(' ')[6]
                UserName = $Tail.Split(' ')[7]
                ClientIP = $Tail.Split(' ')[8]
                UserAgent = $Tail.Split(' ')[9]
                Referer = $Tail.Split(' ')[10]
                HTTPstatus = $Tail.Split(' ')[11]
                HTTPSstatus = $Tail.Split(' ')[12]
                Win32status = $Tail.Split(' ')[13]
                TimeTaken = $Tail.Split(' ')[14]
                Compliant = if ($WebIP -match $Tail.Split(' ')[2]) {

                    "Yes"
                }

                else {

                    "No"
                }
            }
        }
    }
}