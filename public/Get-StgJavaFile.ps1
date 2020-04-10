function Get-StgJavaFile {
<#
    .SYNOPSIS
        Remove all *.jpp,*.java files for vulnerability 76717.

    .DESCRIPTION
        Remove all *.jpp,*.java files for vulnerability 76717.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76717
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
            $JavaFiles = Get-ChildItem -Path $env:SystemDrive -File -Include *.jpp,*.java -Recurse -Force -ErrorAction SilentlyContinue

            if ($JavaFiles) {

                $JavaFiles | Remove-Item -Force
                $PostFiles = Get-ChildItem -Path $env:SystemDrive -File -Include *.jpp,*.java -Recurse -Force -ErrorAction SilentlyContinue

                [pscustomobject] @{

                    Id = "V-76717"
                    ComputerName = $env:ComputerName
                    FilesRemoved = $JavaFiles
                    Compliant = if (-not ($PostFiles)) {

                        "Yes: Files found and removed"
                    } else {

                        "No: File removal incomplete"
                    }
                }
            } else {
                [pscustomobject] @{
                    Id = "V-76717"
                    ComputerName = $env:ComputerName
                    FilesToRemove = "No files found"
                    Compliant = $true
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