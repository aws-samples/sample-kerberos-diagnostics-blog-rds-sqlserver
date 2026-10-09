##  Kerberos Authentication for RDS SQL Server with Self-Managed Active Directory Companion Scripts

These scripts are companion tools for the blog post:
  "Kerberos Authentication for Amazon RDS for SQL Server with Self-Managed
   Active Directory"

They help you validate that your environment is correctly configured for RDS
SQL Server to join a Self-Managed Active Directory domain using Kerberos
authentication before you attempt the domain join itself.

--------------------------------------------------------------------------------
SCRIPTS
--------------------------------------------------------------------------------

1. Test-ADConnectivity.ps1
   -------------------------
   Tests network connectivity from an EC2 instance (in the same VPC/subnet as
   your RDS instance) to one or more Active Directory Domain Controllers.

   What it checks:
   - TCP ports required for domain join and Kerberos authentication:
       53  (DNS), 88 (Kerberos), 135 (RPC Endpoint Mapper), 389 (LDAP),
       445 (SMB), 464 (Kerberos password change), 636 (LDAPS)
   - RPC ephemeral ports (49152-65535) via dynamic discovery through port 135.
       If portqry is installed, it enumerates and tests the actual active RPC
       endpoints. Otherwise it confirms port 135 is reachable and advises that
       the full range must be open in the security group.
   - UDP port 53 (DNS) via a real DNS query.
   - Kerberos / DC locator reachability using nltest, scoped to each specific DC
       passed in -DCs (not just any DC in the domain). A PASS confirms the
       network path to that DC is open for Kerberos/LDAP.

   Run this from an EC2 instance in the same VPC and subnet as your RDS
   instance to simulate the network path RDS will use during domain join.

   Usage:
     ### Single DC
     .\Test-ADConnectivity.ps1 -DCs "172.31.80.20" -Domain "corp.example.com"

     ### Multiple DCs
     .\Test-ADConnectivity.ps1 -DCs "10.0.0.10","10.0.0.11" -Domain "corp.example.com"

     ### Custom timeout (default is 2000 ms)
     .\Test-ADConnectivity.ps1 -DCs "10.0.0.10" -Domain "corp.example.com" -TimeoutMs 3000

   Prerequisites:
   - Run from a Windows EC2 instance in the same VPC/subnet as the RDS instance
   - nltest.exe must be available (included in Windows Server by default; install
     RSAT on Windows client machines)
   - portqry.exe is optional but recommended for RPC ephemeral port discovery
     (download from Microsoft at https://www.microsoft.com/en-us/download/details.aspx?id=17148)
   - No domain membership required on the test EC2 instance


2. Check-RdsDomainPermissions.ps1
   ---------------------------------
   Verifies that the Active Directory service account used for the RDS domain
   join has all required AD and DNS permissions. Run this from a domain-joined
   Windows machine with the ActiveDirectory and DnsServer PowerShell modules.

   What it checks:
   Section 1 - Domain Join permissions on the target OU:
     - Create Computer objects
     - Delete Computer objects
     - Validated Write: DNS Host Name (on computer objects)
     - Validated Write: Service Principal Name (on computer objects)

   Section 2 - DNS CNAME permissions on the DNS zone:
     - List contents
     - Read all properties
     - Read permissions
     - Create all child objects (required to add CNAME records)
     - Delete all child objects (required to remove CNAME records)

   Section 3 - Group memberships (informational):
     - Lists all groups the service account belongs to
     - Notes if the account is in DnsAdmins or Domain Admins

   Section 4 - Functional tests:
     - DNS read via Get-DnsServerResourceRecord
     - AD OU read via Get-ADObject

   Usage:
     ### Minimum required parameters
     .\Check-RdsDomainPermissions.ps1 `
         -DomainFqdn "corp.example.com" `
         -ServiceAccount "CORP\rds-svc"

     ### With a specific OU (recommended — defaults to CN=Computers if omitted)
     .\Check-RdsDomainPermissions.ps1 `
         -DomainFqdn "corp.example.com" `
         -ServiceAccount "CORP\rds-svc" `
         -OuDn "OU=RDS,OU=Servers,DC=corp,DC=example,DC=com"

     ### Targeting a specific Domain Controller
     .\Check-RdsDomainPermissions.ps1 `
         -DomainFqdn "corp.example.com" `
         -ServiceAccount "CORP\rds-svc" `
         -OuDn "OU=RDS,OU=Servers,DC=corp,DC=example,DC=com" `
         -DcName "dc01.corp.example.com"

   Parameters:
     -DomainFqdn      (Required) The fully qualified domain name, e.g. corp.example.com
     -ServiceAccount  (Required) The AD service account in DOMAIN\username or UPN format
     -OuDn            (Optional) Distinguished Name of the OU where RDS will create
                                 computer objects. Defaults to CN=Computers,<domain DN>.
                                 Always specify this for production environments.
     -DcName          (Optional) Hostname or FQDN of the Domain Controller to target.
                                 Defaults to the local machine / domain default.
                                 Specify this if DNS zone lookup fails.

   Prerequisites:
   - Must be run from a domain-joined Windows machine
   - ActiveDirectory PowerShell module (RSAT: Active Directory DS and LDS Tools)
   - DnsServer PowerShell module (RSAT: DNS Server Tools)
   - The account running the script needs read access to AD ACLs
     (Domain Admin or Delegated Read rights on the OU and DNS zone)


--------------------------------------------------------------------------------
RECOMMENDED WORKFLOW
--------------------------------------------------------------------------------

1. Launch a Windows EC2 instance in the same VPC and subnet as your RDS instance.

2. Run Test-ADConnectivity.ps1 from that EC2 instance, passing your DC IP(s) and
   domain FQDN. All TCP ports and the Kerberos locator should PASS before
   proceeding. Fix any security group or NACL rules blocking required ports.

3. From a domain-joined Windows machine (can be the same EC2 instance if it is
   domain-joined, or your admin workstation), run Check-RdsDomainPermissions.ps1
   with the service account and OU you plan to use for RDS domain join. All
   permission checks in Sections 1 and 2 should show [PASS].

4. Once both scripts show all green, proceed with the RDS SQL Server domain join

--------------------------------------------------------------------------------
NOTES
--------------------------------------------------------------------------------

- These scripts validate the NETWORK PATH and AD PERMISSIONS from the perspective
  of the test machine. They do not validate SQL Server Kerberos authentication
  itself (MSSQLSvc SPN registration, Kerberos logins, constrained delegation) —
  those are validated after the domain join is complete.

- UDP Kerberos (port 88) and LDAP (port 389) are NOT probed directly as individual
  UDP port tests because AWS security groups silently drop blocked UDP packets,
  making generic UDP probes unreliable (timeout ≠ blocked). Instead,
  Test-ADConnectivity.ps1 uses nltest to request a real Kerberos TGT from the
  specific DC, which reliably confirms or denies the Kerberos network path.

- RPC ephemeral ports (49152-65535) are dynamically assigned. Testing a random
  port in that range may fail simply because no RPC service is listening on that
  exact port at that moment — this is NOT evidence of a security group issue.
  The scripts handle this correctly by querying the Endpoint Mapper (port 135)
  first and, if portqry is available, testing only the ports that are actually
  registered with active RPC endpoints.

--------------------------------------------------------------------------------
RELATED RESOURCES
--------------------------------------------------------------------------------

- AWS Documentation: Setting up self-managed Active Directory with an Amazon RDS
  for SQL Server DB instance
  https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_SQLServerWinAuth.html

- Microsoft Documentation: Active Directory firewall ports
  https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements

- portqry download (optional, for RPC ephemeral port discovery):
  https://www.microsoft.com/en-us/download/details.aspx?id=17148

================================================================================


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

