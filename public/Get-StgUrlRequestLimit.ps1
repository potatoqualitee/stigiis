function Get-StgUrlRequestLimit {
<#
    .SYNOPSIS
        Configure and verify URL Request Limit settings for vulnerability 76817.

    .DESCRIPTION
        Configure and verify URL Request Limit settings for vulnerability 76817.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76817
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
            $MaxUrl = 4096

            foreach($webname in $webnames) {

                $preconfigMaxUrl = Get-WebConfigurationProperty -Filter $filterpath -Name MaxUrl

                Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name MaxUrl -Value $MaxUrl -Force

                $postconfigurationMaxUrl = Get-WebConfigurationProperty -Filter $filterpath -Name MaxUrl

                [pscustomobject] @{
                    Id = "V-76817"
                    ComputerName = $env:ComputerName
                    Sitename = $webname
                    PreConfiugrationMaxUrl = $preconfigMaxUrl.Value
                    PostConfiugrationMaxUrl = $postconfigurationMaxUrl.Value
                    Compliant = if ($postconfigurationMaxUrl.Value -le $MaxUrl) {
                        $true
                    } else {
                        "No: Value must be $MaxUrl or less"
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