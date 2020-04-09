function Invoke-Command2
{
<#
	.SYNOPSIS
		An Invoke-Command wrapper with integrated session management.

	.DESCRIPTION
		This wrapper command around Invoke-Command allows conveniently calling remote calls.

		- It uses the PSFComputer parameter class, and is thus a lot more flexible in accepted input
		- It automatically reuses sessions specified for input
		- It automatically establishes new sessions, tracks usage and retires sessions that have timed out.

		Using this command, it is no longer necessary to first establish a connection and then manually handle the session object.
		Just point the command at the computer and it will remember.
		It also reuses sessions across multiple commands that call it.

		Note:
		Special connection conditions (like a custom application name, alternative authentication schemes, etc.) are not supported and require using New-PSSession to establish the connection.
		Once that session has been established, the session object can be used with this command and will be used for command invocation.

	.PARAMETER ComputerName
		The computer(s) to invoke the command on.
		Accepts all kinds of things that legally point at a computer, including DNS names, ADComputer objects, IP Addresses, SQL Server connection strings, CimSessions or PowerShell Sessions.
		It will reuse PSSession objects if specified (and not include them in its session management).

	.PARAMETER ScriptBlock
		The code to execute.

	.PARAMETER ArgumentList
		The arguments to pass into the scriptblock.

	.PARAMETER Credential
		Credentials to use when establishing connections.
		Note: These will be ignored if there already exists an established connection.

	.PARAMETER HideComputerName
		Indicates that this cmdlet omits the computer name of each object from the output display. By default, the name of the computer that generated the object appears in the display.

	.PARAMETER ThrottleLimit
		Specifies the maximum number of concurrent connections that can be established to run this command. If you omit this parameter or enter a value of 0, the default value, 32, is used.

	.EXAMPLE
		PS C:\> Invoke-PSFCommand -ScriptBlock $ScriptBlock

		Runs the $scriptblock against the local computer.

	.EXAMPLE
		PS C:\> Invoke-PSFCommand -ScriptBlock $ScriptBlock (Get-ADComputer -Filter "name -like 'srv-db*'")

		Runs the $scriptblock against all computers in AD with a name that starts with "srv-db".
#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSPossibleIncorrectUsageOfAssignmentOperator", "")]
	[CmdletBinding(HelpUri = 'https://psframework.org/documentation/commands/PSFramework/Invoke-PSFCommand')]
	param (
		[PSFComputer[]]
		[Alias('Session')]
		$ComputerName = $env:COMPUTERNAME,

		[Parameter(Mandatory)]
		[scriptblock]
		$ScriptBlock,

		[object[]]
		$ArgumentList,

		[System.Management.Automation.CredentialAttribute()]
		[System.Management.Automation.PSCredential]
		$Credential
    )
	process
	{
		foreach ($computer in $ComputerName)
		{
            Write-Verbose -Message "Connecting to $computer"
            $null = Invoke-PSFCommand -ComputerName $computer -Credential $Credential -ErrorAction Stop -ScriptBlock {
                # test to make sure the WebAdministration module exists.
                # Loading it each time is no big deal because Invoke-PSFCommand uses sessions
                Import-Module WebAdministration -ErrorAction Stop
            }
            Invoke-PSFCommand @PSBoundParameters -ErrorAction Stop
        }
	}
}