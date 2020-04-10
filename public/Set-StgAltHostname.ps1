function Set-StgAltHostname {
<#
    .SYNOPSIS
        Configure and verify Alternate Hostname settings for vulnerability 76883.

    .DESCRIPTION
        Configure and verify Alternate Hostname settings for vulnerability 76883.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76883
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
            $pspath = "MACHINE/WEBROOT/APPHOST"
            $webnames = (Get-Website).Name
            $filterpath = "system.webserver/serverRuntime"

            foreach($webname in $webnames) {
                $hostname = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name alternateHostname).Value

                if (-not $hostname) {
                    $AlternateHostName = "$(($webname).Replace(' ','')).$((Get-CimInstance -ClassName Win32_ComputerSystem).Domain)"
                    write-warning $AlternateHostName
                    #Set-WebConfigurationProperty -PSPath $pspath/$($webname) -Filter $filterpath -Name alternateHostname -Value $AlternateHostName
                }

                $postconfigHostname = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name alternateHostname).Value

                [pscustomobject] @{
                    Id = "V-76883"
                    ComputerName = $env:ComputerName
                    Sitename = $webname
                    PreConfigHostname  = $hostname
                    PostConfigHostname = $postconfigHostname
                    Compliant          = if ($postconfigHostname) {
                        $true
                    } else {
                        $false
                    }
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Sitename, Compliant, PreConfigHostname, PostConfigHostname |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}