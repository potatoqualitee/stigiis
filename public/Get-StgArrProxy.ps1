function Get-StgArrProxy {
<#
    .SYNOPSIS
        Disable proxy settings for Application Request Routing feature for vulnerability 76703.

    .DESCRIPTION
        Disable proxy settings for Application Request Routing feature for vulnerability 76703.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76703
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
        $scriptblock= {
            $WebPath = "MACHINE/WEBROOT/APPHOST"
            $webnames = (Get-Website).Name
            foreach($webname in $webnames) {
                try {
                    #Disable proxy for Application Request Routing
                    Set-WebConfigurationProperty -Location $WebPath -Filter "system.webServer/proxy" -Name "Enabled" -Value "False"
                    $ProxyValue = Get-WebConfigurationProperty -PSPath $WebPath -Filter "system.webServer/proxy" -Name "Enabled"

                    [pscustomobject] @{
                        Id = "V-76703"
                        ComputerName = $env:ComputerName
                        Value = $ProxyValue
                    }
                } catch {
                    [pscustomobject] @{
                        Id = "V-76703"
                        ComputerName = $env:ComputerName
                        Value = "N/A: Application Request Routing not available"
                    }
                }
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