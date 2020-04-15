#
# Module manifest for module 'stigiis'
#
# Generated by: Chrissy LeMaire
#
@{
    # Version number of this module.
    ModuleVersion     = '0.0.1'

    # ID used to uniquely identify this module
    GUID              = 'dcef37ea-2803-4048-9fff-1f8f0c4b6786'

    # Author of this module
    Author            = 'Chrissy LeMaire'

    # Company or vendor of this module
    CompanyName       = 'Chrissy LeMaire'

    # Copyright statement for this module
    Copyright         = '2020 Chrissy LeMaire'

    # Description of the functionality provided by this module
    Description       = 'DISA STIG Automation for IIS'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '3.0'

    # Format files (xml) to be loaded when importing this module
    # "xml\dbatools.Format.ps1xml"
    FormatsToProcess       = @("bin\xml\stigiis.Format.ps1xml")

    # Assemblies that must be imported into the global environment prior to importing this module
    RequiredModules    = @(
        @{ ModuleName = 'PSFramework'; ModuleVersion = '1.0.19' }
    )

    # Script module or binary module file associated with this manifest.
    RootModule        = 'stigiis.psm1'

    FunctionsToExport = @(
        'Find-StgCommand',
        'Get-StgAltHostname',
        'Get-StgAnonymousAuth',
        'Get-StgAppPoolEventLog',
        'Get-StgAppPoolPingSetting',
        'Get-StgAppPoolQueueLength',
        'Get-StgAppPoolRapidFailInterval',
        'Get-StgAppPoolRapidFailProtection',
        'Get-StgAppPoolRecycle',
        'Get-StgAppPoolRecyclePrivateMemory',
        'Get-StgAppPoolRecycleVirtualMemory',
        'Get-StgAppPoolTimeout',
        'Get-StgArrProxy',
        'Get-StgAuthRule',
        'Get-StgCertificate',
        'Get-StgCgiIsapi',
        'Get-StgClientCertificate',
        'Get-StgCompression',
        'Get-StgContentLength',
        'Get-StgDebugSetting',
        'Get-StgDefaultDocument',
        'Get-StgDirectoryBrowsing',
        'Get-StgDoubleEscape',
        'Get-StgEncryptionValidation',
        'Get-StgErrorDetail',
        'Get-StgFso',
        'Get-StgGroupMembership',
        'Get-StgHighBit',
        'Get-StgIndexConfiguration',
        'Get-StgInstalledFeature',
        'Get-StgInstalledSoftware',
        'Get-StgJavaFile',
        'Get-StgLogAcl',
        'Get-StgLogBaseline',
        'Get-StgLogCustom',
        'Get-StgLogDataField',
        'Get-StgLogSetting',
        'Get-StgMaxConnection',
        'Get-StgMaxQueryString',
        'Get-StgMimeMapping',
        'Get-StgPrintService',
        'Get-StgSessionSecurity',
        'Get-StgSessionStateCookie',
        'Get-StgSessionStateInProc',
        'Get-StgSessionTimeout',
        'Get-StgSSLSetting',
        'Get-StgTlsSetting',
        'Get-StgTrustLevel',
        'Get-StgUnlistedFileExtension',
        'Get-StgUriRegistry',
        'Get-StgUrlRequestLimit',
        'Get-StgWebDav',
        'Remove-StgJavaFile',
        'Remove-StgWebDav',
        'Set-StgAltHostname',
        'Set-StgAnonymousAuth',
        'Set-StgAppPoolEventLog',
        'Set-StgAppPoolPingSetting',
        'Set-StgAppPoolQueueLength',
        'Set-StgAppPoolRapidFailInterval',
        'Set-StgAppPoolRapidFailProtection',
        'Set-StgAppPoolRecycle',
        'Set-StgAppPoolRecyclePrivateMemory',
        'Set-StgAppPoolRecycleVirtualMemory',
        'Set-StgAppPoolTimeout',
        'Set-StgArrProxy',
        'Set-StgAuthRule',
        'Set-StgCgiIsapi',
        'Set-StgClientCertificate',
        'Set-StgCompression',
        'Set-StgContentLength',
        'Set-StgDebugSetting',
        'Set-StgDefaultDocument',
        'Set-StgDirectoryBrowsing',
        'Set-StgDoubleEscape',
        'Set-StgEncryptionValidation',
        'Set-StgErrorDetail',
        'Set-StgHighBit',
        'Set-StgLogCustom',
        'Set-StgLogDataField',
        'Set-StgLogSetting',
        'Set-StgMaxConnection',
        'Set-StgMaxQueryString',
        'Set-StgMimeMapping',
        'Set-StgSessionSecurity',
        'Set-StgSessionStateCookie',
        'Set-StgSessionStateInProc',
        'Set-StgSessionTimeout',
        'Set-StgSSLSetting',
        'Set-StgTlsSetting',
        'Set-StgTrustLevel',
        'Set-StgUnlistedFileExtension',
        'Set-StgUrlRequestLimit',
        'Uninstall-StgPrintService'
    )

    CmdletsToExport   = @( )
    AliasesToExport   = @( )

    PrivateData       = @{
        # PSData is module packaging and gallery metadata embedded in PrivateData
        # It's for rebuilding PowerShellGet (and PoshCode) NuGet-style packages
        # We had to do this because it's the only place we're allowed to extend the manifest
        # https://connect.microsoft.com/PowerShell/feedback/details/421837
        PSData = @{
            # The primary categorization of this module (from the TechNet Gallery tech tree).
            Category     = 'Security'

            # Keyword tags to help users find this module via navigations and search.
            Tags         = @('security', 'disa', 'stig', 'compliance', 'iis')

            # The web address of an icon which can be used in galleries to represent this module
            IconUri      = 'https://user-images.githubusercontent.com/8278033/68308152-a886c180-00ac-11ea-880c-ef6ff99f5cd4.png'

            # Indicates this is a pre-release/testing version of the module.
            IsPrerelease = 'False'
        }
    }
}