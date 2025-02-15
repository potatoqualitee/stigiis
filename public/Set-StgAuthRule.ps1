function Set-StgAuthRule {
<#
    .SYNOPSIS
        Configure and verify Authorization Rules settings for vulnerability 76771.

    .DESCRIPTION
        Configure and verify Authorization Rules settings for vulnerability 76771.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76771
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Set-StgAuthRule -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgAuthRule -ComputerName web01 -Credential ad\webadmin

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
            $filterpath = "system.web/authorization/allow"

            Start-Process -FilePath "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList "unlock", "config", "-section:$filterpath" -Wait
            Start-Process -FilePath "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList "unlock", "config", "-section:system.web/authorization" -Wait

            $Settings = "[@roles='' and @users='*' and @verbs='']"
            $preconfig = Get-WebConfigurationProperty -Filter $filterpath -Name Users

            $null = Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter "$($filterpath)$($Settings)" -Name Users -Value "Administrators"
            $null = Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter "system.web/authorization" -Name "." -Value @{users="?"} -Type deny

            $postconfig = Get-WebConfigurationProperty -Filter $filterpath -Name Users

            if ($postconfig.Value -eq "Administrators") {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id = "V-76771"
                ComputerName = $env:COMPUTERNAME
                Before = $preconfig.Value
                After = $postconfig.Value
                Compliant = $compliant
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

