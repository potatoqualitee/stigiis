function Set-StgDefaultDocument {
    <#
    .SYNOPSIS
        Configure and verify Default Document settings for vulnerability 76831.

    .DESCRIPTION
        Configure and verify Default Document settings for vulnerability 76831.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76831
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Set-StgDefaultDocument -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgDefaultDocument -ComputerName web01 -Credential ad\webadmin

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
            $webnames = (Get-Website).Name
            $filterpath = "system.webServer/defaultDocument"
            foreach ($webname in $webnames) {
                $preconfigDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled
                if ($preconfigDefaultDocumentEnabled -eq $false) {
                    $null = Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name Enabled -Value "True"
                }

                $preconfigDefaultDocumentFiles = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Files

                if ($preconfigDefaultDocumentFiles.Count -eq 0) {
                    $null = Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter "system.webServer/defaultDocument/files" -Name "." -Value @{value = "Default.aspx"}
                }

                $postconfigDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled
                $postconfigDefaultDocumentFiles = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Files

                if ($postconfigDefaultDocumentEnabled.Value -and $postconfigDefaultDocumentFiles.Count -gt 0) {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id                           = "V-76831"
                    ComputerName                 = $env:COMPUTERNAME
                    SiteName                     = $webname
                    BeforeDefaultDocumentEnabled = $preconfigDefaultDocumentEnabled.Value
                    BeforeDefaultDocumentFiles   = $preconfigDefaultDocumentFiles.Count
                    AfterDefaultDocumentEnabled  = $postconfigDefaultDocumentEnabled.Value
                    AfterDefaultDocumentFiles    = $postconfigDefaultDocumentFiles.Count
                    Compliant                    = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Before, After, SiteName, BeforeDefaultDocumentEnabled, AfterDefaultDocumentEnabled, BeforeDefaultDocumentFiles, AfterDefaultDocumentFiles, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

