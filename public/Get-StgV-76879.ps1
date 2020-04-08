function Get-StgV-76879 {
<#
.SYNOPSIS
    Configure and verify Application Pool Rapid-Fail Protection settings for vulnerability 76879.

.DESCRIPTION
    Configure and verify Application Pool Rapid-Fail Protection settings for vulnerability 76879.

    .NOTES
        Tags: V-76879
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
        $filterpath = 'failure.rapidFailProtection'

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        $AppPools = (Get-IISAppPool).Name

        foreach($Pool in $AppPools) {

            $PreConfigRapidFailEnabled = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath -Value $true

            $PostConfigRapidFailEnabled = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

            [pscustomobject] @{
                Vulnerability = "V-76877"
                Computername = $env:COMPUTERNAME
                ApplicationPool = $Pool
                PreConfigRapidFailEnabled = $PreConfigRapidFailEnabled
                PostConfigRapidFailEnabled = $PostConfigRapidFailEnabled
                Compliant = if ($PostConfigRapidFailEnabled -eq $true) {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}