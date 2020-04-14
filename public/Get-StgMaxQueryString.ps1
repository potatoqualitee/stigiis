function Get-StgMaxQueryString {
    <#
    .SYNOPSIS
        Configure and verify Maximum Query String settings for vulnerability 76821.

    .DESCRIPTION
        Configure and verify Maximum Query String settings for vulnerability 76821.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76821
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgMaxQueryString -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgMaxQueryString -ComputerName web01 -Credential ad\webadmin

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
            $webnames = (Get-Website).Name
            $filterpath = "system.webServer/security/requestFiltering/requestLimits"
            [Int]$MaxQueryString = 2048

            foreach ($webname in $webnames) {
                $MaxQueryString = Get-WebConfigurationProperty -Filter $filterpath -Name maxQueryString
                Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name maxQueryString -Value $MaxQueryString -Force
                $postconfigurationMaxQueryString = Get-WebConfigurationProperty -Filter $filterpath -Name maxQueryString

                if ($postconfigurationMaxQueryString.Value -le $MaxQueryString) {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id           = "V-76821"
                    ComputerName = $env:COMPUTERNAME
                    SiteName     = $webname
                    Value       = $MaxQueryString.Value
                    After        = $postconfigurationMaxQueryString.Value
                    Compliant    = $compliant
                    Notes        = "Value must be $MaxQueryString or less"
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, Value, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
