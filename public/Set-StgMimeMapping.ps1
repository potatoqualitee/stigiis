function Set-StgMimeMapping {
    <#
    .SYNOPSIS
        Remove required MIME mappings for vulnerability 76711 & 76797.

    .DESCRIPTION
        Remove required MIME mappings for vulnerability 76711 & 76797.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76711, V-76797
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Set-StgMimeMapping -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgMimeMapping -ComputerName web01 -Credential ad\webadmin

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
            #Pre-Configuration MIME map collection
            $preMimeConfig = (Get-WebConfiguration //staticcontent).Collection

            #Adjusted MIM map collection
            $NewCollection = ($preMimeConfig | where {$_.fileextension -ne ".exe" -and $_.fileextension -ne ".dll" -and $_.fileextension -ne ".com" -and $_.fileextension -ne ".bat" -and $_.fileextension -ne ".csh"})

            #Set new configurations
            $null = Set-WebConfigurationProperty //staticContent -Name Collection -InputObject $NewCollection
            $postMimeConfig = (Get-WebConfiguration //staticcontent).Collection

            [pscustomobject] @{
                Id                = "V-76711", "V-76797"
                ComputerName      = $env:COMPUTERNAME
                BeforeExtenstions = $preMimeConfig.FileExtension
                BeforeCount       = $preMimeConfig.Count
                AfterExtenstions  = $postMimeConfig.FileExtension
                AfterCount        = $postMimeConfig.Count
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, BeforeCount, AfterCount, BeforeExtenstions, AfterExtenstions, AfterCount |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

