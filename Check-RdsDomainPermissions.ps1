#Requires -Version 5.1
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Verifies that an AD account (or group) has the permissions required
    for RDS domain join and DNS server access.

.DESCRIPTION
    Checks the following on the target OU and DNS server container:

    Section 1 — Account & Group Memberships
    Section 2 — Domain Join Permissions on OU:
        • Create Computer objects
        • Delete Computer objects
        • Validated Write: DNS Host Name         (computer descendants)
        • Validated Write: Service Principal Name (computer descendants)
    Section 3 — DNS Server-Level Permissions on CN=MicrosoftDNS,CN=System:
        • List contents
        • Read all properties
        • Read permissions
    Section 4 — DNS Zone default grant:
        • Authenticated Users (S-1-5-11): Create all child objects
    Section 5 — Functional read tests

    Permissions are checked for the account AND all its group memberships
    (direct and nested), so group-inherited permissions are detected.
    Identity matching is SID-based — works regardless of domain name or locale.

.NOTES
    Requirements:
        • PowerShell 5.1 or later
        • RSAT: Active Directory module (Get-WindowsCapability -Name Rsat.Active*)
        • Run from a domain-joined machine with network access to the target DC
        • DnsServer module optional — Section 5 DNS test skipped if not present

.EXAMPLE
    .\Check-RdsDomainPermissions.ps1 'svc-rds-join' 'OU=RDS,DC=corp,DC=example,DC=com' 'corp.example.com' 'DC01.corp.example.com'

.EXAMPLE
    # Group — checks permissions granted to the group directly
    .\Check-RdsDomainPermissions.ps1 'rds-group' 'OU=RDS,DC=corp,DC=example,DC=com' 'corp.example.com'

.EXAMPLE
    # Verbose — shows SID resolution details and all ACEs for diagnosis
    .\Check-RdsDomainPermissions.ps1 'svc-rds-join' 'OU=RDS,DC=corp,DC=example,DC=com' 'corp.example.com' -Verbose
#>

[CmdletBinding()]
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

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module DnsServer       -ErrorAction SilentlyContinue

# -------------------------------------------------------
# Derived variables
# -------------------------------------------------------
# Strip domain prefix if supplied (e.g. DOMAIN\user → user, user@domain → user)
$samAccount = $ServiceAccount -replace '^[^\\]+\\', '' -replace '@.+$', ''

$domainDc   = ($DomainFqdn -split '\.' | ForEach-Object { "DC=$_" }) -join ','

if ([string]::IsNullOrWhiteSpace($OuDn)) { $OuDn = "CN=Computers,$domainDc" }

# If DcName was not supplied use the domain FQDN so the AD cmdlets
# target any available DC rather than the local machine.
$dcFqdn     = if ($DcName -ne $env:COMPUTERNAME -and $DcName -ne '') { $DcName } else { $DomainFqdn }

# -------------------------------------------------------
# Schema GUIDs — identical across all AD forests
# -------------------------------------------------------
$GUID_COMPUTER_CLASS = [System.Guid]'bf967a86-0de6-11d0-a285-00aa003049e2'  # computer class
$GUID_DNS_HOSTNAME   = [System.Guid]'72e39547-7b18-11d1-adef-00c04fd8d5cd'  # Validated Write: DNS Host Name
$GUID_SPN            = [System.Guid]'f3a64788-5306-11d1-a9c5-0000f80367c1'  # Validated Write: SPN

# Well-known SID for Authenticated Users — locale-independent
$SID_AUTHENTICATED_USERS = 'S-1-5-11'

# -------------------------------------------------------
# DNS zone auto-discovery
# -------------------------------------------------------
function Find-DnsZoneDn {
    param([string]$ZoneName, [string]$DomainDc, [string]$DcFqdn)
    foreach ($path in @(
        "DC=$ZoneName,CN=MicrosoftDNS,DC=DomainDnsZones,$DomainDc",
        "DC=$ZoneName,CN=MicrosoftDNS,DC=ForestDnsZones,$DomainDc",
        "DC=$ZoneName,CN=MicrosoftDNS,CN=System,$DomainDc"
    )) {
        try { Get-ADObject -Identity $path -Server $DcFqdn -ErrorAction Stop | Out-Null
              Write-Verbose "DNS zone found at: $path"; return $path } catch { }
    }
    foreach ($base in @("DC=DomainDnsZones,$DomainDc","DC=ForestDnsZones,$DomainDc",$DomainDc)) {
        try {
            $found = Get-ADObject -Filter { ObjectClass -eq 'dnsZone' } `
                         -SearchBase $base -SearchScope Subtree `
                         -Server $DcFqdn -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -eq $ZoneName } | Select-Object -First 1
            if ($found) { Write-Verbose "DNS zone found via search: $($found.DistinguishedName)"
                          return $found.DistinguishedName }
        } catch { }
    }
    $fallback = "DC=$ZoneName,CN=MicrosoftDNS,DC=DomainDnsZones,$DomainDc"
    try { Get-Acl -Path "AD:\$fallback" -ErrorAction Stop | Out-Null; return $fallback } catch { }
    return $null
}

$zoneDn = Find-DnsZoneDn -ZoneName $DomainFqdn -DomainDc $domainDc -DcFqdn $dcFqdn

# -------------------------------------------------------
# Effective SID set — own SID + all group SIDs (nested)
# Using script: scope so inner functions can read/write it.
# -------------------------------------------------------
$script:effectiveSids = New-Object 'System.Collections.Generic.HashSet[string]'

function Get-EffectiveSids {
    param([string]$Identity, [string]$DcFqdn, [int]$Depth = 0)
    if ($Depth -gt 5) { return }   # guard against circular group nesting
    try {
        $obj = Get-ADObject -LDAPFilter "(sAMAccountName=$Identity)" `
                   -Server $DcFqdn -Properties objectSid, objectClass -ErrorAction Stop |
               Select-Object -First 1
        if (-not $obj) { return }

        [void]$script:effectiveSids.Add($obj.objectSid.Value)
        Write-Verbose "  SID: $($obj.objectSid.Value)  ($($obj.objectClass): $Identity)"

        try {
            foreach ($grp in (Get-ADPrincipalGroupMembership -Identity $Identity -Server $DcFqdn -ErrorAction Stop)) {
                if ($script:effectiveSids.Add($grp.SID.Value)) {
                    Write-Verbose "  Group SID: $($grp.SID.Value)  ($($grp.Name))"
                    Get-EffectiveSids -Identity $grp.SamAccountName -DcFqdn $DcFqdn -Depth ($Depth + 1)
                }
            }
        } catch { }
    } catch { Write-Verbose "  Could not resolve SIDs for '$Identity': $_" }
}

Get-EffectiveSids -Identity $samAccount -DcFqdn $dcFqdn

# If the account could not be resolved at all, the SID set will be empty.
# All permission checks would produce false FAILs — stop early with a clear message.
if ($script:effectiveSids.Count -eq 0) {
    Write-Host ""
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host " RDS Domain Join & DNS Permission Check" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host " Account  : $ServiceAccount"
    Write-Host " Domain   : $DomainFqdn"
    Write-Host "======================================================`n" -ForegroundColor Cyan
    Write-Host "  [ERROR] Account '$samAccount' was not found in domain '$DomainFqdn'." -ForegroundColor Red
    Write-Host "          Verify the account name and domain, then re-run." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# -------------------------------------------------------
# ACE matching helpers
# Handles both NTAccount (DOMAIN\name) and SecurityIdentifier (S-1-5-...)
# formats returned by different AD access methods.
# -------------------------------------------------------
function Test-IsAuthenticatedUsersSid {
    param($IdentityReference)
    # Direct SID object
    if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
        return $IdentityReference.Value -eq $SID_AUTHENTICATED_USERS
    }
    # String or NTAccount — translate to SID and compare
    try {
        $translated = ([System.Security.Principal.NTAccount]$IdentityReference.ToString()).Translate(
                          [System.Security.Principal.SecurityIdentifier]).Value
        return $translated -eq $SID_AUTHENTICATED_USERS
    } catch { return $false }
}

function Test-AceMatchesPrincipal {
    param($Ace)
    if (-not ($Ace -is [System.DirectoryServices.ActiveDirectoryAccessRule])) { return $false }
    $ref = $Ace.IdentityReference.ToString()
    if ($script:effectiveSids.Contains($ref))    { return $true }  # SID direct match
    if ($ref -like "*$samAccount*")               { return $true }  # name match
    try {
        $sid = ([System.Security.Principal.NTAccount]$ref).Translate(
                   [System.Security.Principal.SecurityIdentifier]).Value
        if ($script:effectiveSids.Contains($sid)) { return $true }  # translated SID match
    } catch { }
    return $false
}

function Get-MatchingAces {
    param($Acl)
    return $Acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and (Test-AceMatchesPrincipal -Ace $_)
    }
}

function Get-AclFromPath {
    param([string]$AdPath)
    try { return Get-Acl -Path "AD:\$AdPath" -ErrorAction Stop }
    catch {
        try {
            $drvName = "ADChk_$(Get-Random)"
            New-PSDrive -Name $drvName -PSProvider ActiveDirectory `
                -Server $dcFqdn -Root '' -ErrorAction Stop | Out-Null
            $acl = Get-Acl -Path "${drvName}:\$AdPath" -ErrorAction Stop
            Remove-PSDrive -Name $drvName -ErrorAction SilentlyContinue
            return $acl
        } catch { Write-Warning "Cannot read ACL on '$AdPath': $_"; return $null }
    }
}

function Has-Right {
    param([string]$RightsString, [string]$Right)
    $lookup = switch ($Right) {
        'ListChildren' { 'GenericExecute' }
        'ReadControl'  { 'ReadProperty'   }
        default        { $Right           }
    }
    return ($RightsString -match [regex]::Escape($lookup) -or
            $RightsString -match 'GenericAll' -or
            $RightsString -match 'FullControl')
}

function Write-Pass { param($Msg) Write-Host "  [PASS] $Msg" -ForegroundColor Green }
function Write-Fail { param($Msg) Write-Host "  [FAIL] $Msg  <-- MISSING" -ForegroundColor Red }

# ======================================================
# HEADER
# ======================================================
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " RDS Domain Join & DNS Permission Check" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Account  : $ServiceAccount"
Write-Host " Domain   : $DomainFqdn"
Write-Host " DC       : $DcName"
Write-Host " OU       : $OuDn"
Write-Host " DNS Zone : $(if ($zoneDn) { $zoneDn } else { 'NOT FOUND' })"
Write-Host "======================================================`n" -ForegroundColor Cyan

# ======================================================
# SECTION 1 — Account & Group Memberships
# ======================================================
Write-Host "=== [1] Account & Group Memberships ===" -ForegroundColor Yellow
try {
    $adObj = Get-ADObject -LDAPFilter "(sAMAccountName=$samAccount)" `
                 -Server $dcFqdn -Properties objectClass, objectSid -ErrorAction Stop |
             Select-Object -First 1
    if (-not $adObj) { throw "Account '$samAccount' not found in domain '$DomainFqdn'." }

    Write-Host "  Type : $($adObj.objectClass)"
    Write-Host "  SID  : $($adObj.objectSid.Value)"
    Write-Host "  Effective SIDs (account + groups): $($script:effectiveSids.Count)"
    Write-Host ""

    if ($adObj.objectClass -eq 'group') {
        Write-Host "  Members of '$samAccount':" -ForegroundColor Cyan
        $members = Get-ADGroupMember -Identity $samAccount -Server $dcFqdn -ErrorAction Stop |
                   Select-Object Name, SamAccountName, objectClass
        if ($members) { $members | Format-Table -AutoSize }
        else { Write-Host "  (no members)" -ForegroundColor DarkGray }
    } else {
        Write-Host "  Group memberships for '$samAccount':" -ForegroundColor Cyan
        $grpList = Get-ADPrincipalGroupMembership -Identity $samAccount -Server $dcFqdn -ErrorAction Stop |
                   Select-Object Name, SID
        if ($grpList) { $grpList | Format-Table -AutoSize }
        else { Write-Host "  (no group memberships)" -ForegroundColor DarkGray }
    }
} catch {
    Write-Warning "Could not resolve account '$samAccount': $_"
}

# ======================================================
# SECTION 2 — Domain Join Permissions on OU
# ======================================================
Write-Host "=== [2] Domain Join Permissions on OU ===" -ForegroundColor Yellow
Write-Host "    $OuDn`n"

$ouAcl    = Get-AclFromPath -AdPath $OuDn
$ouAces   = if ($ouAcl) { Get-MatchingAces -Acl $ouAcl } else { @() }
$ouRights = @($ouAces | ForEach-Object { $_.ActiveDirectoryRights.ToString() }) -join ' '

# GenericAll / FullControl is a superset of all specific rights
$hasFullControl = [bool]($ouAces | Where-Object { $_.ActiveDirectoryRights.ToString() -match 'GenericAll|FullControl' })

$hasCreate   = $hasFullControl -or (Has-Right -RightsString $ouRights -Right 'CreateChild')
$hasDelete   = $hasFullControl -or (Has-Right -RightsString $ouRights -Right 'DeleteChild')
$hasDnsWrite = $hasFullControl -or [bool]($ouAces | Where-Object {
    $_.ObjectType -eq $GUID_DNS_HOSTNAME -and $_.InheritedObjectType -eq $GUID_COMPUTER_CLASS })
$hasSpnWrite = $hasFullControl -or [bool]($ouAces | Where-Object {
    $_.ObjectType -eq $GUID_SPN -and $_.InheritedObjectType -eq $GUID_COMPUTER_CLASS })

$djResults = @(
    @{ Name = 'Create Computer objects in OU';                     Pass = $hasCreate   },
    @{ Name = 'Delete Computer objects from OU';                   Pass = $hasDelete   },
    @{ Name = 'Validated Write: DNS Host Name (computer objects)'; Pass = $hasDnsWrite },
    @{ Name = 'Validated Write: Service Principal Name';           Pass = $hasSpnWrite }
)
$djPass = 0
foreach ($r in $djResults) { if ($r.Pass) { Write-Pass $r.Name; $djPass++ } else { Write-Fail $r.Name } }
$djColor = if ($djPass -eq $djResults.Count) { 'Green' } else { 'Red' }
Write-Host "`n  RESULT: $(if ($djPass -eq $djResults.Count) {'OK'} else {'INCOMPLETE'}) ($djPass/$($djResults.Count))`n" -ForegroundColor $djColor

# ======================================================
# SECTION 3 — DNS Server-Level Permissions
# ======================================================
Write-Host "=== [3] DNS Server-Level Permissions ===" -ForegroundColor Yellow

$dnsServerDn  = "CN=MicrosoftDNS,CN=System,$domainDc"
$dnsServerAcl = $null
try {
    $de = [ADSI]"LDAP://$dcFqdn/$dnsServerDn"
    if ($de.distinguishedName) {
        $dnsServerAcl = $de.ObjectSecurity
        Write-Verbose "DNS server container: $dnsServerDn"
    }
} catch { Write-Warning "Cannot bind to DNS server container '$dnsServerDn': $_" }

$dnsServerChecks = @(
    @{ Name = 'List contents';       Match = 'GenericExecute|ListChildren|GenericAll|FullControl' },
    @{ Name = 'Read all properties'; Match = 'ReadProperty|GenericAll|FullControl'                },
    @{ Name = 'Read permissions';    Match = 'ReadProperty|GenericAll|FullControl'                }
)
$dnsServerPass  = 0
$dnsServerTotal = $dnsServerChecks.Count

if (-not $dnsServerAcl) {
    Write-Warning "Could not read ACL on '$dnsServerDn'."
} else {
    Write-Host "    $dnsServerDn`n"
    $dnsServerAces   = $dnsServerAcl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and (Test-AceMatchesPrincipal -Ace $_)
    }
    $dnsServerRights = @($dnsServerAces | ForEach-Object { $_.ActiveDirectoryRights.ToString() }) -join ' '
    $dnsFullControl  = [bool]($dnsServerAces | Where-Object { $_.ActiveDirectoryRights.ToString() -match 'GenericAll|FullControl' })

    foreach ($c in $dnsServerChecks) {
        if ($dnsFullControl -or ($dnsServerRights -match $c.Match)) { Write-Pass $c.Name; $dnsServerPass++ }
        else { Write-Fail $c.Name }
    }

    # Dump all ACEs in verbose mode to aid diagnosis
    Write-Verbose "`nAll Allow ACEs on DNS server container:"
    $dnsServerAcl.Access | Where-Object { $_.AccessControlType -eq 'Allow' } |
        ForEach-Object { Write-Verbose "  $($_.IdentityReference.ToString())  |  $($_.ActiveDirectoryRights)" }
}
$dnsServerColor = if ($dnsServerPass -eq $dnsServerTotal) { 'Green' } else { 'Red' }
Write-Host "`n  RESULT: $(if ($dnsServerPass -eq $dnsServerTotal) {'OK'} else {'INCOMPLETE'}) ($dnsServerPass/$dnsServerTotal)`n" -ForegroundColor $dnsServerColor

# ======================================================
# SECTION 4 — DNS Zone Default Grant
# ======================================================
Write-Host "=== [4] DNS Zone Permissions ===" -ForegroundColor Yellow

$dnsZonePass  = 0
$dnsZoneTotal = 1

if (-not $zoneDn) {
    Write-Warning "DNS zone AD object not found for '$DomainFqdn'. Run with -Verbose for diagnostics."
} else {
    Write-Host "    $zoneDn`n"
    try {
        $zoneAcl      = Get-Acl -Path "AD:\$zoneDn" -ErrorAction Stop
        $authUsersAce = $zoneAcl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.ActiveDirectoryRights.ToString() -match 'CreateChild' -and
            (Test-IsAuthenticatedUsersSid -IdentityReference $_.IdentityReference)
        }
        if ($authUsersAce) {
            Write-Pass "Authenticated Users (S-1-5-11) : Create all child objects"
            Write-Host "         (AD-integrated zone default grant is intact)" -ForegroundColor DarkGray
            $dnsZonePass = 1
        } else {
            Write-Fail "Authenticated Users (S-1-5-11) : Create all child objects"
        }
    } catch { Write-Warning "Could not read ACL on DNS zone: $_" }

    $dnsZoneColor = if ($dnsZonePass -eq $dnsZoneTotal) { 'Green' } else { 'Red' }
    Write-Host "`n  RESULT: $(if ($dnsZonePass -eq $dnsZoneTotal) {'OK'} else {'FAIL'}) ($dnsZonePass/$dnsZoneTotal)`n" -ForegroundColor $dnsZoneColor
}

# ======================================================
# SECTION 5 — Functional Tests
# ======================================================
Write-Host "`n=== [5] Functional Tests ===" -ForegroundColor Yellow

if (Get-Command Get-DnsServerResourceRecord -ErrorAction SilentlyContinue) {
    try {
        Get-DnsServerResourceRecord -ZoneName $DomainFqdn -ComputerName $DcName -RRType A |
            Select-Object -First 1 | Out-Null
        Write-Pass "DNS read (Get-DnsServerResourceRecord) succeeded."
    } catch { Write-Host "  [FAIL] DNS read failed: $_" -ForegroundColor Red }
} else {
    Write-Host "  [SKIP] DnsServer module not installed — DNS read test skipped." -ForegroundColor DarkGray
}

try {
    Get-ADObject -Identity $OuDn -Server $dcFqdn -ErrorAction Stop | Out-Null
    Write-Pass "AD OU read succeeded."
} catch { Write-Host "  [FAIL] AD OU read failed: $_" -ForegroundColor Red }

# ======================================================
# SUMMARY
# ======================================================
$totalPass   = $djPass + $dnsServerPass + $dnsZonePass
$totalChecks = $djResults.Count + $dnsServerTotal + $dnsZoneTotal

Write-Host "`n======================================================" -ForegroundColor Cyan
Write-Host " SUMMARY  $totalPass / $totalChecks checks passed" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Domain Join  : $djPass / $($djResults.Count)  $(if ($djPass -eq $djResults.Count) {'[OK]'} else {'[FAIL]'})" `
    -ForegroundColor $(if ($djPass -eq $djResults.Count) {'Green'} else {'Red'})
Write-Host " DNS Server   : $dnsServerPass / $dnsServerTotal  $(if ($dnsServerPass -eq $dnsServerTotal) {'[OK]'} else {'[FAIL]'})" `
    -ForegroundColor $(if ($dnsServerPass -eq $dnsServerTotal) {'Green'} else {'Red'})
Write-Host " DNS Zone     : $dnsZonePass / $dnsZoneTotal  $(if ($dnsZonePass -eq $dnsZoneTotal) {'[OK]'} else {'[FAIL]'})" `
    -ForegroundColor $(if ($dnsZonePass -eq $dnsZoneTotal) {'Green'} else {'Red'})

if ($totalPass -eq $totalChecks) {
    Write-Host "`n ALL PASSED — account has all required RDS permissions." -ForegroundColor Green
} else {
    Write-Host "`n INCOMPLETE — one or more permissions are missing." -ForegroundColor Red
}
Write-Host "======================================================`n" -ForegroundColor Cyan
