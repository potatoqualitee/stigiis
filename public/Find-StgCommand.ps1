function Find-StgCommand {
    <#
    .SYNOPSIS
        Finds stigiis commands searching through the inline help text

    .DESCRIPTION
        Finds stigiis commands searching through the inline help text, building a consolidated json index and querying it because Get-Help is too slow

    .PARAMETER Tag
        Finds all commands tagged with this auto-populated tag

    .PARAMETER Author
        Finds all commands tagged with this author

    .PARAMETER MinimumVersion
        Finds all commands tagged with this auto-populated minimum version

    .PARAMETER MaximumVersion
        Finds all commands tagged with this auto-populated maximum version

    .PARAMETER Rebuild
        Rebuilds the index

    .PARAMETER Pattern
        Searches help for all commands in stigiis for the specified pattern and displays all results

    .PARAMETER Confirm
        Confirms overwrite of index

    .PARAMETER WhatIf
        Displays what would happen if the command is run

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Find-StgCommand V-76883

        For lazy typers: finds all commands searching the entire help for V-76883

    .EXAMPLE
        PS C:\> Find-StgCommand -Pattern hostname

        For rigorous typers: finds all commands searching the entire help for the word hostname

    .EXAMPLE
        PS C:\> Find-StgCommand -Tag V-76883

        Finds all commands tagged with V-76883

    .EXAMPLE
        PS C:\> Find-StgCommand -Tag V-76811, V-76883

        Finds all commands tagged with BOTH V-76811 and V-76883
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$Pattern,
        [String[]]$Tag,
        [string]$Author,
        [string]$MinimumVersion,
        [string]$MaximumVersion,
        [switch]$Rebuild,
        [switch]$EnableException
    )
    begin {
        function Get-StgTrimmedString($Text) {
            return $Text.Trim() -replace '(\r\n){2,}', "`n"
        }

        $tagsRex = ([regex]'(?m)^[\s]{0,15}Tags:(.*)$')
        $authorRex = ([regex]'(?m)^[\s]{0,15}Author:(.*)$')
        $minverRex = ([regex]'(?m)^[\s]{0,15}MinimumVersion:(.*)$')
        $maxverRex = ([regex]'(?m)^[\s]{0,15}MaximumVersion:(.*)$')

        function Get-StgHelp([string]$commandName) {
            $availability = 'Windows, Linux, macOS'
            if ($commandName -in $script:noncoresmo -or $commandName -in $script:windowsonly) {
                $availability = 'Windows only'
            }
            try {
                $thishelp = Get-Help $commandName -Full
            } catch {
                Stop-PSFFunction -Message "Issue getting help for $commandName" -Target $commandName -ErrorRecord $_ -Continue
            }

            $thebase = @{ }
            $thebase.CommandName = $commandName
            $thebase.Name = $thishelp.Name

            $thebase.Availability = $availability

            $alias = Get-Alias -Definition $commandName -ErrorAction SilentlyContinue
            $thebase.Alias = $alias.Name -Join ','

            ## fetch the description
            $thebase.Description = $thishelp.Description.Text

            ## fetch examples
            $thebase.Examples = Get-StgTrimmedString -Text ($thishelp.Examples | Out-String -Width 200)

            ## fetch help link
            $thebase.Links = ($thishelp.relatedLinks).NavigationLink.Uri

            ## fetch the synopsis
            $thebase.Synopsis = $thishelp.Synopsis

            ## fetch the syntax
            $thebase.Syntax = Get-StgTrimmedString -Text ($thishelp.Syntax | Out-String -Width 600)

            ## store notes
            $as = $thishelp.AlertSet | Out-String -Width 600

            ## fetch the tags
            $tags = $tagsrex.Match($as).Groups[1].Value
            if ($tags) {
                $thebase.Tags = $tags.Split(',').Trim()
            }
            ## fetch the author
            $author = $authorRex.Match($as).Groups[1].Value
            if ($author) {
                $thebase.Author = $author.Trim()
            }

            ## fetch MinimumVersion
            $MinimumVersion = $minverRex.Match($as).Groups[1].Value
            if ($MinimumVersion) {
                $thebase.MinimumVersion = $MinimumVersion.Trim()
            }

            ## fetch MaximumVersion
            $MaximumVersion = $maxverRex.Match($as).Groups[1].Value
            if ($MaximumVersion) {
                $thebase.MaximumVersion = $MaximumVersion.Trim()
            }

            ## fetch Parameters
            $parameters = $thishelp.parameters.parameter | Where-Object Name -notin 'SqlCredential', 'Credential', 'EnableException', 'WhatIf', 'Confirm'

            $command = Get-Command $commandName
            $params = @()
            foreach ($p in $parameters) {
                $paramAlias = $command.parameters[$p.Name].Aliases
                $paramDescr = Get-StgTrimmedString -Text ($p.Description | Out-String -Width 200)
                $params += , @($p.Name, $paramDescr, ($paramAlias -Join ','), ($p.Required -eq $true), $p.PipelineInput, $p.DefaultValue)
            }

            $thebase.Params = $params

            [pscustomobject]$thebase
        }

        function Get-StgIndex() {
            if ($Pscmdlet.ShouldProcess($dest, "Recreating index")) {
                $Stgmodule = Get-Module -Name stigiis
                $allCommands = $Stgmodule.ExportedCommands.Values | Where-Object CommandType -In 'Function', 'Cmdlet' | Sort-Object -Property Name | Select-Object -Unique | Where-Object Name -notin 'Find-StgCommand'
                #Had to add Unique because Select-StgObject was getting populated twice once written to the index file

                $helpcoll = New-Object System.Collections.Generic.List[System.Object]
                foreach ($command in $allCommands) {
                    $x = Get-StgHelp "$command"
                    $helpcoll.Add($x)
                }
                $dest = Resolve-Path "$script:ModuleRoot\bin\stigiis-index.json"
                $helpcoll | ConvertTo-Json -Depth 4 | Out-File $dest -Encoding UTF8
            }
        }
    }
    process {
        $Pattern = $Pattern.TrimEnd("s")
        $idxFile = Resolve-Path "$script:ModuleRoot\bin\stigiis-index.json"
        if (-not (Test-Path $idxFile) -or $Rebuild) {
            Write-PSFMessage -Level Verbose -Message "Rebuilding index into $idxFile"
            $swRebuild = [system.diagnostics.stopwatch]::StartNew()
            Get-StgIndex
            Write-PSFMessage -Level Verbose -Message "Rebuild done in $($swRebuild.ElapsedMilliseconds)ms"
        }
        $consolidated = Get-Content -Raw $idxFile | ConvertFrom-Json
        $result = $consolidated
        if ($Pattern.Length -gt 0) {
            $result = $result | Where-Object { $_.PsObject.Properties.Value -like "*$Pattern*" }
        }

        if ($Tag.Length -gt 0) {
            foreach ($t in $Tag) {
                $result = $result | Where-Object Tags -Contains $t
            }
        }

        if ($Author.Length -gt 0) {
            $result = $result | Where-Object Author -Like "*$Author*"
        }

        if ($MinimumVersion.Length -gt 0) {
            $result = $result | Where-Object MinimumVersion -GE $MinimumVersion
        }

        if ($MaximumVersion.Length -gt 0) {
            $result = $result | Where-Object MaximumVersion -LE $MaximumVersion
        }

        Select-DefaultView -InputObject $result -Property CommandName, Synopsis
    }
}