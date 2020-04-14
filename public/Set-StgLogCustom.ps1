function Set-StgLogCustom {
    <#
    .SYNOPSIS
        Check, configure, and verify Custom Logging Fields for vulnerabilities 76687, 76689, 76789, & 76791.

    .DESCRIPTION
        Check, configure, and verify Custom Logging Fields for vulnerabilities 76687, 76689, 76789, & 76791.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76687, V-76689, V-76789, V-76791
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Set-StgLogCustom -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgLogCustom -ComputerName web01 -Credential ad\webadmin

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
            #Custom logging fields
            $Connection = [pscustomobject] @{
                LogFieldName = "Connection"
                SourceType   = "RequestHeader"
                SourceName   = "Connection"
            }

            $Warning = [pscustomobject] @{
                LogFieldName = "Warning"
                SourceType   = "RequestHeader"
                SourceName   = "Warning"
            }

            $HTTPConnection = [pscustomobject] @{
                LogFieldName = "HTTPConnection"
                SourceType   = "ServerVariable"
                SourceName   = "HTTPConnection"
            }

            $UserAgent = [pscustomobject] @{
                LogFieldName = "User-Agent"
                SourceType   = "RequestHeader"
                SourceName   = "User-Agent"
            }

            $ContentType = [pscustomobject] @{
                LogFieldName = "Content-Type"
                SourceType   = "RequestHeader"
                SourceName   = "Content-Type"
            }

            $HTTPUserAgent = [pscustomobject] @{
                LogFieldName = "HTTP_USER_AGENT"
                SourceType   = "ServerVariable"
                SourceName   = "HTTP_USER_AGENT"
            }

            $CustomFields = @(
                $Connection,
                $Warning,
                $HTTPConnection,
                $UserAgent,
                $ContentType,
                $HTTPUserAgent
            )

            #All website names
            $webnames = (Get-Website).Name

            foreach ($Custom in $CustomFields) {
                foreach ($webname in $webnames) {
                    try {
                        #Set custom logging fields
                        New-ItemProperty "IIS:\Sites\$webname" -Name "logfile.customFields.collection" -Value $Custom -ErrorAction Stop
                    } catch {
                        # usually duplication errors
                        Write-Verbose -Message "$_"
                    }
                }
            }

            foreach ($webname in $webnames) {
                #Post-Configuration custom fields
                $postconfig = (Get-ItemProperty "IIS:\Sites\$webname" -Name "logfile.customFields.collection")
                if ($postconfig.logFieldName -contains "Connection" -and $postconfig.logFieldName -contains "Warning" -and $postconfig.logFieldName -contains "HTTPConnection" -and $postconfig.logFieldName -contains "User-Agent" -and $postconfig.logFieldName -contains "Content-Type" -and $postconfig.logFieldName -contains "HTTP_USER_AGENT") {
                    $compliant = $true
                } else {
                    $compliant = $false

                }
                [pscustomobject] @{
                    Id           = "V-76687", "V-76689", "V-76789", "V-76791"
                    SiteName     = $webname
                    CustomFields = $postconfig.logFieldName
                    Compliant    = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, CustomFields, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

