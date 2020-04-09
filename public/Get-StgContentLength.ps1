function Get-StgContentLength {
<#
    .SYNOPSIS
        Configure and verify Maximum Content Length settings for vulnerability 76819.

    .DESCRIPTION
        Configure and verify Maximum Content Length settings for vulnerability 76819.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76819
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
            $webnames = (Get-Website).Name
            $filterpath = "system.webServer/security/requestFiltering/requestLimits"
            $MaxContentLength = 30000000



            foreach($webname in $webnames) {

                $PreConfigMaxContentLength = Get-WebConfigurationProperty -Filter $filterpath -Name maxAllowedContentLength

                Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name maxAllowedContentLength -Value $MaxContentLength -Force

                $PostConfigurationMaxContentLength = Get-WebConfigurationProperty -Filter $filterpath -Name maxAllowedContentLength

                [pscustomobject] @{
                    Vulnerability = "V-76819"
                    ComputerName = $env:ComputerName
                    Sitename = $webname
                    PreConfiugrationMaxContentLength = $PreConfigMaxContentLength.Value
                    PostConfiugrationMaxContentLength = $PostConfigurationMaxContentLength.Value
                    Compliant = if ($PostConfigurationMaxContentLength.Value -le $MaxContentLength) {

                        "Yes"
                    } else {
                        "No: Value must be $MaxContentLength or less"
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