function Get-StgLogCustom {
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
                SourceType = "RequestHeader"
                SourceName = "Connection"
            }

            $Warning = [pscustomobject] @{
                LogFieldName = "Warning"
                SourceType = "RequestHeader"
                SourceName = "Warning"
            }

            $HTTPConnection = [pscustomobject] @{
                LogFieldName = "HTTPConnection"
                SourceType = "ServerVariable"
                SourceName = "HTTPConnection"
            }

            $UserAgent = [pscustomobject] @{
                LogFieldName = "User-Agent"
                SourceType = "RequestHeader"
                SourceName = "User-Agent"
            }

            $ContentType = [pscustomobject] @{
                LogFieldName = "Content-Type"
                SourceType = "RequestHeader"
                SourceName = "Content-Type"
            }

            $HTTPUserAgent = [pscustomobject] @{
                LogFieldName = "HTTP_USER_AGENT"
                SourceType = "ServerVariable"
                SourceName = "HTTP_USER_AGENT"
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

            foreach($Custom in $CustomFields) {

                foreach($webname in $webnames) {

                    try {
                        #Set custom logging fields
                        New-ItemProperty "IIS:\Sites\$($webname)" -Name "logfile.customFields.collection" -Value $Custom -ErrorAction Stop
                    }
                    catch {
                        # usually duplication errors
                        Write-Verbose -Message "$_"
                    }
                }
            }

            foreach($webname in $webnames) {

                #Post-Configuration custom fields
                $PostConfig = (Get-ItemProperty "IIS:\Sites\$($webname)" -Name "logfile.customFields.collection")

                [pscustomobject] @{

                    Vulnerability = "V-76687, V-76689, V-76789, V-76791"
                    SiteName = $webname
                    CustomFields = $($PostConfig.logFieldName)
                    Compliant = if ($PostConfig.logFieldName -contains "Connection" -and $PostConfig.logFieldName -contains "Warning" -and $PostConfig.logFieldName -contains "HTTPConnection" -and $PostConfig.logFieldName -contains "User-Agent" -and $PostConfig.logFieldName -contains "Content-Type" -and $PostConfig.logFieldName -contains "HTTP_USER_AGENT") {

                        "Yes"
                    }

                    else {

                        "No"
                    }
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