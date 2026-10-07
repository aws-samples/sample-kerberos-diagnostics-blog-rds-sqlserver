param(
    [Parameter(Mandatory=$true)]
    [string]$DomainFqdn,
    [Parameter(Mandatory=$true)]
    [string]$ServiceAccount,
    [Parameter(Mandatory=$true)]
    [string]$OuDn,
    [Parameter(Mandatory=$false)]
    [string]$DcName = $env:COMPUTERNAME
)

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module DnsServer       -ErrorAction SilentlyContinue

$samAccount  = $ServiceAccount -replace '.*\\', ''
$domainParts = $DomainFqdn -split '\.' | ForEach-Object { "DC=$_" }
$domainDc    = $domainParts -join ','
if ([string]::IsNullOrWhiteSpace($OuDn)) { $OuDn = "CN=Computers,$domainDc" }

# Known GUIDs
$GUID_COMPUTER_OBJECT   = "bf967a86-0de6-11d0-a285-00aa003049e2"  # computer objectClass
$GUID_VALIDATED_DNS     = "f3a64788-5306-11d1-a9c5-0000f80367c1"  # Validated Write: DNS Host Name
$GUID_VALIDATED_SPN     = "72e39547-7b18-11d1-adef-00c04fd8d5cd"  # Validated Write: Service Principal Name

# Auto-discover DNS zone DN
# FIX: added -Server $dcFqdn to every Get-ADObject call so the query always targets
#       the correct DC regardless of the machine's default domain context.
#       Also added extra candidate paths and a wider fallback search base.
function Find-DnsZoneDn($zoneName, $domainDc, $dcFqdn) {
    $candidates = @(
        "DC=$zoneName,CN=MicrosoftDNS,DC=DomainDnsZones,$domainDc",
        "DC=$zoneName,CN=MicrosoftDNS,DC=ForestDnsZones,$domainDc",
        "DC=$zoneName,CN=MicrosoftDNS,CN=System,$domainDc"
    )
    foreach ($path in $candidates) {
        try {
            Get-ADObject -Identity $path -Server $dcFqdn -ErrorAction Stop | Out-Null
            Write-Host "  [DEBUG] DNS zone found at: $path" -ForegroundColor DarkGray
            return $path
        } catch { }
    }

    # Fallback 1: broad subtree search across entire domain NC — requires -Server to target the right DC
    Write-Host "  [DEBUG] Candidates not found, trying broad subtree search..." -ForegroundColor DarkGray
    foreach ($searchBase in @("DC=DomainDnsZones,$domainDc", "DC=ForestDnsZones,$domainDc", $domainDc)) {
        try {
            $found = Get-ADObject -Filter { ObjectClass -eq "dnsZone" } `
                -SearchBase $searchBase -SearchScope Subtree `
                -Server $dcFqdn -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $zoneName } |
                Select-Object -First 1
            if ($found) {
                Write-Host "  [DEBUG] Found via subtree search: $($found.DistinguishedName)" -ForegroundColor DarkGray
                return $found.DistinguishedName
            }
        } catch { }
    }

    # Fallback 2: try constructing the DN directly and verifying via Get-Acl (works even when
    #             Get-ADObject fails due to naming context routing issues)
    $fallbackPath = "DC=$zoneName,CN=MicrosoftDNS,DC=DomainDnsZones,$domainDc"
    try {
        Get-Acl -Path "AD:\$fallbackPath" -ErrorAction Stop | Out-Null
        Write-Host "  [DEBUG] Zone confirmed via Get-Acl fallback: $fallbackPath" -ForegroundColor DarkGray
        return $fallbackPath
    } catch { }

    return $null
}

# Resolve $DcName to a proper FQDN for -Server parameter.
# If -DcName was not supplied (defaults to $env:COMPUTERNAME), use the domain FQDN so
# the AD cmdlets target any available DC in the domain rather than the local machine.
$dcFqdn = if ($DcName -ne $env:COMPUTERNAME -and $DcName -ne "") { $DcName } else { $DomainFqdn }

$zoneDn = Find-DnsZoneDn $DomainFqdn $domainDc $dcFqdn

Write-Host "`n======================================================" -ForegroundColor Cyan
Write-Host " RDS Domain Join & DNS Permission Check" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Account  : $ServiceAccount"
Write-Host " Domain   : $DomainFqdn"
Write-Host " DC       : $DcName"
Write-Host " OU/CN    : $OuDn"
Write-Host " DNS Zone : $(if ($zoneDn) { $zoneDn } else { 'NOT FOUND' })"
Write-Host "======================================================`n" -ForegroundColor Cyan

function Get-Aces($adPath, $samAccount) {
    try {
        $acl = Get-Acl -Path "AD:\$adPath" -ErrorAction Stop
        return $acl.Access | Where-Object {
            $_.AccessControlType -eq "Allow" -and
            $_.IdentityReference -like "*$samAccount*"
        }
    } catch {
        # FIX: if the default AD: PSDrive targets the wrong domain, retry by temporarily
        #      creating a drive anchored to the correct server
        try {
            $drvName = "ADCheck_$(Get-Random)"
            New-PSDrive -Name $drvName -PSProvider ActiveDirectory `
                -Server $dcFqdn -Root "" -ErrorAction Stop | Out-Null
            $acl = Get-Acl -Path "${drvName}:\$adPath" -ErrorAction Stop
            Remove-PSDrive -Name $drvName -ErrorAction SilentlyContinue
            return $acl.Access | Where-Object {
                $_.AccessControlType -eq "Allow" -and
                $_.IdentityReference -like "*$samAccount*"
            }
        } catch {
            Write-Host "  [ERROR] Cannot read ACL on '$adPath': $_" -ForegroundColor Red
            return @()
        }
    }
}

function Has-Right($rightsString, $right) {
    # AD right serialization gotcha documented in rds-aws-learnings.md:
    #
    #   ListChildren  -> .NET serializes this as "GenericExecute" when read back via Get-Acl.
    #                    Matching "ListChildren" against the returned string will always fail.
    #
    #   ReadControl   -> Does NOT appear as a standalone token in the serialized string.
    #                    It is absorbed into the combined rights value. When ReadProperty is
    #                    present, ReadControl is implicitly covered — match on ReadProperty instead.
    #
    # All other rights (ReadProperty, CreateChild, DeleteChild, WriteProperty) serialize as-is.

    $lookup = switch ($right) {
        "ListChildren" { "GenericExecute" }  # ListChildren -> GenericExecute
        "ReadControl"  { "ReadProperty"   }  # ReadControl  -> covered by ReadProperty
        default        { $right           }
    }

    return ($rightsString -match [regex]::Escape($lookup) -or
            $rightsString -match "GenericAll" -or
            $rightsString -match "FullControl")
}

# -------------------------------------------------------
# SECTION 1: Domain Join — check actual required ACEs
# Based on code analysis: CreateChild, DeleteChild,
# Validated Write DNS Hostname, Validated Write SPN
# -------------------------------------------------------
Write-Host "=== [1] Domain Join Permissions on OU ===" -ForegroundColor Yellow
Write-Host "    $OuDn`n"

$aces   = Get-Aces $OuDn $samAccount
$rights = ($aces).ActiveDirectoryRights -join ' '

$hasCreateDelete    = Has-Right $rights "CreateChild"
$hasWriteProperty   = Has-Right $rights "WriteProperty"

# Check Validated Write ACEs by GUID
$hasValidatedDns = $aces | Where-Object {
    $_.ObjectType.ToString() -eq $GUID_VALIDATED_DNS -and
    $_.InheritedObjectType.ToString() -eq $GUID_COMPUTER_OBJECT
}
$hasValidatedSpn = $aces | Where-Object {
    $_.ObjectType.ToString() -eq $GUID_VALIDATED_SPN -and
    $_.InheritedObjectType.ToString() -eq $GUID_COMPUTER_OBJECT
}

$djResults = @(
    @{ Name = "Create Computer objects in OU";                    Pass = $hasCreateDelete },
    @{ Name = "Delete Computer objects from OU";                  Pass = ($aces | Where-Object { $_.ActiveDirectoryRights -match "DeleteChild" }) -ne $null },
    @{ Name = "Validated Write: DNS Host Name (on computer obj)"; Pass = $hasValidatedDns -ne $null },
    @{ Name = "Validated Write: Service Principal Name";          Pass = $hasValidatedSpn -ne $null }
)

$djPass = 0
foreach ($r in $djResults) {
    if ($r.Pass) {
        Write-Host "  [PASS] $($r.Name)" -ForegroundColor Green
        $djPass++
    } else {
        Write-Host "  [FAIL] $($r.Name)  <-- MISSING" -ForegroundColor Red
    }
}

$djColor = if ($djPass -eq $djResults.Count) { "Green" } else { "Red" }
Write-Host "`n  RESULT: $(if ($djPass -eq $djResults.Count) {'OK'} else {'INCOMPLETE'}) ($djPass/$($djResults.Count))`n" -ForegroundColor $djColor

# -------------------------------------------------------
# SECTION 2: DNS CNAME Permissions
# -------------------------------------------------------
Write-Host "=== [2] DNS CNAME Permissions on Zone ===" -ForegroundColor Yellow

if (-not $zoneDn) {
    Write-Host "  [ERROR] DNS zone AD object not found for '$DomainFqdn'" -ForegroundColor Red
    Write-Host "  Tried: DomainDnsZones, ForestDnsZones, CN=System" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Diagnostic: run this manually on a domain-joined machine to find the zone DN:" -ForegroundColor Yellow
    Write-Host "    Get-ADObject -Filter { ObjectClass -eq 'dnsZone' } -SearchBase 'DC=DomainDnsZones,$domainDc' -SearchScope Subtree -Server $dcFqdn | Where-Object { `$_.Name -eq '$DomainFqdn' } | Select DistinguishedName" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  If the above returns nothing, try:" -ForegroundColor Yellow
    Write-Host "    Get-ADObject -Filter { ObjectClass -eq 'dnsZone' } -SearchBase '$domainDc' -SearchScope Subtree -Server $dcFqdn | Select Name, DistinguishedName" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Then re-run this script with -DcName <specific-dc-hostname>" -ForegroundColor Yellow
    Write-Host "  Example: .\Check-RdsDomainPermissions.ps1 -DomainFqdn '$DomainFqdn' -ServiceAccount '$ServiceAccount' -OuDn '$OuDn' -DcName 'dc01.$DomainFqdn'`n" -ForegroundColor Yellow
    $dnsPass = 0
    $dnsTotalChecks = 5
} else {
    Write-Host "    $zoneDn`n"
    $dnsAces   = Get-Aces $zoneDn $samAccount
    $dnsRights = ($dnsAces).ActiveDirectoryRights -join ' '

    $dnsChecks = @(
        @{ Name = "List contents";                                                       Right = "ListChildren" },
        @{ Name = "Read all properties";                                                 Right = "ReadProperty" },
        @{ Name = "Read permissions";                                                    Right = "ReadControl"  },
        @{ Name = "Create all child objects  (Add-DnsServerResourceRecordCName)";        Right = "CreateChild"  },
        @{ Name = "Delete all child objects  (Remove-DnsServerResourceRecord)";          Right = "DeleteChild"  }
    )

    $dnsPass = 0
    foreach ($check in $dnsChecks) {
        if (Has-Right $dnsRights $check.Right) {
            Write-Host "  [PASS] $($check.Name)" -ForegroundColor Green
            $dnsPass++
        } else {
            Write-Host "  [FAIL] $($check.Name)  <-- MISSING" -ForegroundColor Red
        }
    }

    # Diagnostic: show the raw serialized ACE rights strings so mismatches are visible
    Write-Host "`n  [DEBUG] Raw ACE ActiveDirectoryRights for '$samAccount' on DNS zone:" -ForegroundColor DarkGray
    if ($dnsAces) {
        $dnsAces | ForEach-Object {
            Write-Host "    $($_.ActiveDirectoryRights)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "    (none found — account has no Allow ACEs on this object)" -ForegroundColor DarkGray
    }
    Write-Host ""

    $dnsTotalChecks = $dnsChecks.Count
    $dnsColor = if ($dnsPass -eq $dnsTotalChecks) { "Green" } else { "Red" }
    Write-Host "`n  RESULT: $(if ($dnsPass -eq $dnsTotalChecks) {'OK'} else {'INCOMPLETE'}) ($dnsPass/$dnsTotalChecks)`n" -ForegroundColor $dnsColor
}

# -------------------------------------------------------
# SECTION 3: Group Memberships
# -------------------------------------------------------
Write-Host "=== [3] Group Memberships for '$samAccount' ===" -ForegroundColor Yellow
try {
    $groups = Get-ADPrincipalGroupMembership -Identity $samAccount -Server $dcFqdn -ErrorAction Stop |
              Select-Object Name, DistinguishedName
    $groups | Format-Table -AutoSize
    if ($groups.Name -contains "DnsAdmins")    { Write-Host "  [NOTE] In DnsAdmins    — DNS write access via group." -ForegroundColor Green }
    if ($groups.Name -contains "Domain Admins") { Write-Host "  [NOTE] In Domain Admins — all permissions covered." -ForegroundColor Green }
} catch {
    Write-Host "  [WARN] Could not retrieve groups: $_`n" -ForegroundColor Yellow
}

# -------------------------------------------------------
# SECTION 4: Functional Tests
# -------------------------------------------------------
Write-Host "`n=== [4] Functional Tests ===" -ForegroundColor Yellow

try {
    Get-DnsServerResourceRecord -ZoneName $DomainFqdn -ComputerName $DcName -RRType A |
        Select-Object -First 1 | Out-Null
    Write-Host "  [PASS] DNS read (Get-DnsServerResourceRecord) succeeded." -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] DNS read failed: $_" -ForegroundColor Red
}

try {
    Get-ADObject -Identity $OuDn -Server $dcFqdn -ErrorAction Stop | Out-Null
    Write-Host "  [PASS] AD OU read succeeded." -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] AD OU read failed: $_" -ForegroundColor Red
}

# -------------------------------------------------------
# SUMMARY
# -------------------------------------------------------
$totalPass   = $djPass + $dnsPass
$totalChecks = $djResults.Count + $dnsTotalChecks

Write-Host "`n======================================================" -ForegroundColor Cyan
Write-Host " SUMMARY  $totalPass / $totalChecks checks passed" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Domain Join : $djPass / $($djResults.Count)  $(if ($djPass -eq $djResults.Count) {'[OK]'} else {'[FAIL]'})" -ForegroundColor $(if ($djPass -eq $djResults.Count) {"Green"} else {"Red"})
Write-Host " DNS CNAME   : $dnsPass / $dnsTotalChecks  $(if ($dnsPass -eq $dnsTotalChecks) {'[OK]'} else {'[FAIL]'})" -ForegroundColor $(if ($dnsPass -eq $dnsTotalChecks) {"Green"} else {"Red"})

if ($totalPass -eq $totalChecks) {
    Write-Host "`n ALL PASSED — account has all required RDS permissions." -ForegroundColor Green
} else {
    Write-Host "`n INCOMPLETE — account is missing permissions." -ForegroundColor Red
}
Write-Host "======================================================`n" -ForegroundColor Cyan
