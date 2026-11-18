#Requires -Version 5.1
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Grants the AD and DNS permissions required for RDS domain join
    to a service account or security group.

.DESCRIPTION
    Block 1 — AD (OU) Permissions:
        1. CreateChild on computer objects  (OU and all descendants)
        2. DeleteChild on computer objects  (OU and all descendants)
        3. Validated Write: DNS Host Name   (computer object descendants only)
        4. Validated Write: SPN             (computer object descendants only)

    Block 2 — DNS Server-Level Permissions on CN=MicrosoftDNS,CN=System:
        1. List contents
        2. Read all properties
        3. Read permissions

    The DNS zone Authenticated Users default grant (CreateChild) is set
    by AD-integrated zones automatically and is NOT modified by this script.

    Existing ACEs for the account are removed before re-granting in both
    blocks, making the script idempotent — safe to run multiple times.

.NOTES
    Requirements:
        • PowerShell 5.1 or later
        • RSAT: Active Directory module
        • Run from a domain-joined machine with write access to the target OU
          and DNS server container
        • The account running the script must have permission to modify ACLs
          on the OU and CN=MicrosoftDNS,CN=System

.EXAMPLE
    .\Grant-RdsAdPermissions.ps1 'svc-rds-join' 'OU=RDS,DC=corp,DC=example,DC=com' 'corp.example.com' 'DC01.corp.example.com'

.EXAMPLE
    # Group — grants permissions to the group so any member inherits them
    .\Grant-RdsAdPermissions.ps1 'rds-admins' 'OU=RDS,DC=corp,DC=example,DC=com' 'corp.example.com'

.EXAMPLE
    # Verbose — shows each step in detail
    .\Grant-RdsAdPermissions.ps1 'svc-rds-join' 'OU=RDS,DC=corp,DC=example,DC=com' 'corp.example.com' -Verbose
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true,  Position=0)]
    [string]$ServiceAccount,         # SAM account name (user or group), with or without domain prefix

    [Parameter(Mandatory=$true,  Position=1)]
    [string]$OuDn,                   # e.g. OU=RDS,DC=corp,DC=example,DC=com

    [Parameter(Mandatory=$true,  Position=2)]
    [string]$DomainFqdn,             # e.g. corp.example.com

    [Parameter(Mandatory=$false, Position=3)]
    [string]$DcName = $env:COMPUTERNAME
)

Set-StrictMode -Off   # ACL objects from different AD providers may not expose all
                      # properties; we guard each access explicitly instead.

Import-Module ActiveDirectory -ErrorAction Stop

# -------------------------------------------------------
# Derived variables
# -------------------------------------------------------
# Strip domain prefix if supplied (e.g. DOMAIN\user → user, user@domain → user)
$samAccount = $ServiceAccount -replace '^[^\\]+\\', '' -replace '@.+$', ''

$domainDc   = ($DomainFqdn -split '\.' | ForEach-Object { "DC=$_" }) -join ','

# If DcName was not supplied, target any available DC via the domain FQDN
$dcFqdn     = if ($DcName -ne $env:COMPUTERNAME -and $DcName -ne '') { $DcName } else { $DomainFqdn }

$dnsServerDn = "CN=MicrosoftDNS,CN=System,$domainDc"

# -------------------------------------------------------
# Schema GUIDs — identical across all AD forests
# -------------------------------------------------------
$computerClassGuid = [System.Guid]'bf967a86-0de6-11d0-a285-00aa003049e2'  # computer class
$dnsHostNameGuid   = [System.Guid]'72e39547-7b18-11d1-adef-00c04fd8d5cd'  # Validated Write: DNS Host Name
$spnGuid           = [System.Guid]'f3a64788-5306-11d1-a9c5-0000f80367c1'  # Validated Write: SPN
$emptyGuid         = [System.Guid]::Empty

# -------------------------------------------------------
# Resolve SID — works for users, groups, and service accounts
# SID is used for all ACE operations to remain locale/domain-independent
# -------------------------------------------------------
$sid = $null
try {
    $adObj = Get-ADObject -Filter { SamAccountName -eq $samAccount } `
                 -Server $dcFqdn -Properties objectSid, objectClass -ErrorAction Stop |
             Select-Object -First 1
    if (-not $adObj) { throw "Account '$samAccount' not found in domain '$DomainFqdn'." }
    $sid = New-Object System.Security.Principal.SecurityIdentifier($adObj.objectSid.Value)
    Write-Verbose "Resolved '$samAccount' ($($adObj.objectClass)) → SID: $($sid.Value)"
} catch {
    Write-Error "Cannot resolve account '$ServiceAccount': $_"
    exit 1
}

# -------------------------------------------------------
# Helper — remove all existing Allow ACEs for this SID from an ACL
# Ensures idempotency: running the script twice does not accumulate duplicates
# -------------------------------------------------------
function Remove-ExistingAces {
    param(
        [System.DirectoryServices.ActiveDirectorySecurity]$Acl,
        [System.Security.Principal.SecurityIdentifier]$Sid
    )
    $toRemove = $Acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        (& {
            $ref = $_.IdentityReference
            # Compare as SID directly
            if ($ref -is [System.Security.Principal.SecurityIdentifier]) {
                return $ref.Value -eq $Sid.Value
            }
            # Translate NTAccount name to SID and compare
            try {
                $refSid = ([System.Security.Principal.NTAccount]$ref.ToString()).Translate(
                              [System.Security.Principal.SecurityIdentifier]).Value
                return $refSid -eq $Sid.Value
            } catch { return $false }
        })
    }
    $count = 0
    foreach ($ace in @($toRemove)) {
        $Acl.RemoveAccessRule($ace) | Out-Null
        $count++
    }
    Write-Verbose "  Removed $count existing Allow ACE(s) for SID $($Sid.Value)"
}

# ======================================================
# HEADER
# ======================================================
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " RDS Permission Grant" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Account    : $ServiceAccount  ($($adObj.objectClass))"
Write-Host " SID        : $($sid.Value)"
Write-Host " OU         : $OuDn"
Write-Host " DNS Server : $dnsServerDn"
Write-Host "======================================================`n" -ForegroundColor Cyan

# ======================================================
# BLOCK 1 — AD (OU) Permissions
# ======================================================
Write-Host "--- Block 1: AD Permissions on OU ---`n" -ForegroundColor Yellow

try {
    $ouAcl = Get-Acl -Path "AD:\$OuDn" -ErrorAction Stop

    # Remove existing Allow ACEs for this account first (idempotency)
    Remove-ExistingAces -Acl $ouAcl -Sid $sid

    # 1. CreateChild — computer objects — OU and all descendants
    $ouAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $computerClassGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All,
        $emptyGuid
    )))

    # 2. DeleteChild — computer objects — OU and all descendants
    $ouAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $computerClassGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All,
        $emptyGuid
    )))

    # 3. Validated Write: DNS Host Name — computer object descendants only
    $ouAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]::Self,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $dnsHostNameGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $computerClassGuid
    )))

    # 4. Validated Write: SPN — computer object descendants only
    $ouAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]::Self,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $spnGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $computerClassGuid
    )))

    if ($PSCmdlet.ShouldProcess($OuDn, "Set AD domain join ACEs for '$samAccount'")) {
        Set-Acl -Path "AD:\$OuDn" -AclObject $ouAcl -ErrorAction Stop
        Write-Host "  [OK] CreateChild on computer objects (All)"                 -ForegroundColor Green
        Write-Host "  [OK] DeleteChild on computer objects (All)"                 -ForegroundColor Green
        Write-Host "  [OK] Validated Write: DNS Host Name (computer descendants)" -ForegroundColor Green
        Write-Host "  [OK] Validated Write: SPN (computer descendants)"           -ForegroundColor Green
    }
} catch {
    Write-Host "  [ERROR] Failed to set AD permissions: $_" -ForegroundColor Red
}

# ======================================================
# BLOCK 2 — DNS Server-Level Permissions
# ======================================================
Write-Host "`n--- Block 2: DNS Server-Level Permissions ---`n" -ForegroundColor Yellow

try {
    # Use the AD provider (not ADSI) for both read and write — consistent provider
    $dnsAcl = Get-Acl -Path "AD:\$dnsServerDn" -ErrorAction Stop

    # Remove existing Allow ACEs for this account first (idempotency)
    Remove-ExistingAces -Acl $dnsAcl -Sid $sid

    # Required: List contents, Read all properties, Read permissions
    # Added as individual ACEs so each right serialises with its own name
    foreach ($right in @(
        [System.DirectoryServices.ActiveDirectoryRights]::ListChildren,
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::ReadControl
    )) {
        $dnsAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid,
            $right,
            [System.Security.AccessControl.AccessControlType]::Allow
        )))
    }

    if ($PSCmdlet.ShouldProcess($dnsServerDn, "Set DNS server-level ACEs for '$samAccount'")) {
        Set-Acl -Path "AD:\$dnsServerDn" -AclObject $dnsAcl -ErrorAction Stop
        Write-Host "  [OK] List contents"       -ForegroundColor Green
        Write-Host "  [OK] Read all properties" -ForegroundColor Green
        Write-Host "  [OK] Read permissions"    -ForegroundColor Green
    }
} catch {
    Write-Host "  [ERROR] Failed to set DNS server permissions: $_" -ForegroundColor Red
}

# ======================================================
# FOOTER
# ======================================================
Write-Host "`n======================================================" -ForegroundColor Cyan
Write-Host " DONE — Permissions granted for: $ServiceAccount" -ForegroundColor Green
Write-Host "======================================================`n" -ForegroundColor Cyan
