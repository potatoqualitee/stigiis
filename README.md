<img align="left" src=https://user-images.githubusercontent.com/8278033/68308152-a886c180-00ac-11ea-880c-ef6ff99f5cd4.png alt="stigiis logo">

# stigiis
DISA STIG automation module for SQL Server

Add a lil info about how most of the returns are non-compliant reports

## Install

```powershell
Install-Module stigiis -Scope CurrentUser
```

## Examples - Install-DbsAudit

```powershell
# Detect version and create appropriate audit from DISA, output to DATA\Stig\, shutdown on failulre
Install-DbsAudit -SqlInstance sql2017, sql2016, sql2012

# Detect version and create appropriate audit from DISA, output to C:\temp, continue on failulre
Install-DbsAudit -SqlInstance sql2017 -Path C:\temp -OnFaiure Continue
```

## Examples - Set-DbsAcl

```powershell
# Set permissions for the default data, log and backups on sql2017, sql2016, sql2012 by adding
# appropriate permissions for the "AD\SQL Admins" group as well as the SQL Server service accounts.
Set-DbsAcl -SqlInstance sql2017, sql2016, sql2012 -Account "AD\SQL Admins"
```

## Examples - New-DbsDocTemplate

```powershell
# Create a DISA documentation template for 2016
New-DbsDocTemplate -FilePath C:\temp\sql2016.md
```

## Examples - Get-DbsStig

```powershell
# Parse DISA XML and return checklsits for database and instance for SQL Server 2014 and 2016
Get-DbsStig
```

## More Help

Get more help

```powershell
Get-Help Install-DbsAudit -Detailed
```
## Dependencies

- dbatools - For working with SQL
- PSFramework - For PowerShell goodness
- dbachecks - For checking your work
- Pester - Included in dbachecks

