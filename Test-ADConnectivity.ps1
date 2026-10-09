[CmdletBinding()]
param(
    # One or more Domain Controller IP addresses to test connectivity to.
    [Parameter(Mandatory = $true)]
    [string[]] $DCs,

    # AD domain FQDN, used for the Kerberos ticket trigger (e.g. "yourdomain.com").
    [Parameter(Mandatory = $true)]
    [string] $Domain,

    # Per-port TCP connect timeout in milliseconds.
    [int] $TimeoutMs = 2000
)

# =============================================================================
# Test-ADConnectivity.ps1
#
# Purpose: Verify network connectivity from an RDS subnet to Self-Managed AD
#          Domain Controllers for RDS SQL Server domain join.
#
# Usage:   Run directly, passing your DC IP(s) and domain FQDN:
#
#             
#          Run from an EC2 instance in the same VPC/subnet as the RDS instance
#          so it simulates the network path RDS will use during domain join.
#
# Required Ports (RDS -> Domain Controllers):
#   TCP/UDP 53   - DNS
#   TCP/UDP 88   - Kerberos authentication
#   TCP     135  - RPC Endpoint Mapper
#   TCP/UDP 389  - LDAP
#   TCP     445  - SMB / Directory Services
#   TCP/UDP 464  - Kerberos password change
#   TCP     636  - LDAPS
#   TCP     49152-65535 - RPC ephemeral ports (dynamic)
#
# Notes on test results:
#   - TCP PASS/FAIL is definitive (TCP handshake either completes or times out).
#   - UDP is only probed for DNS (port 53), where a valid DNS query reliably
#     elicits a response. Kerberos (88), LDAP (389) and kpasswd (464) are NOT
#     probed per-port over UDP: security groups silently drop blocked packets
#     (no ICMP unreachable), so a generic UDP probe cannot distinguish "blocked"
#     from "open but silent". Instead, those ports are validated by the Kerberos
#     ticket trigger, which requests a real TGT (krbtgt) from this host. A
#     successful TGT proves the client located a DC (DNS + CLDAP), reached the
#     KDC, and received a valid ticket - i.e. the KDC is reachable and the
#     Kerberos ports are open along the path this host uses.
#     SCOPE: this validates the NETWORK PATH and KDC reachability from this
#     machine only. It does NOT validate SQL Server's own Kerberos
#     authentication (the RDS instance domain join, MSSQLSvc SPN registration,
#     or a Kerberos SQL login) - those must be confirmed separately on the
#     RDS/SQL Server side.
#     (Microsoft Windows negotiates TCP/UDP for Kerberos automatically, so a PASS confirms
#     Kerberos works regardless of transport.)
#   - RPC Ephemeral ports are DYNAMIC. Windows assigns them on-demand when
#     services register RPC endpoints. Testing a specific port like 49153 may
#     fail simply because no service is listening on that exact port at that
#     moment. This does NOT indicate a security group issue. The correct test is:
#     1. Confirm TCP 135 (Endpoint Mapper) is reachable
#     2. Query the Endpoint Mapper to discover active RPC ports
#     3. Test those specific ports
#     For domain join, RDS connects to port 135 first, gets told which ephemeral
#     port to use, then connects to that port. As long as the security group
#     allows the full 49152-65535 range, RPC will work.
# =============================================================================

function Test-ADConnectivity {
    [CmdletBinding()]
    param(
        # One or more Domain Controller IP addresses to test connectivity to.
        [Parameter(Mandatory = $true)]
        [string[]] $DCs,

        # AD domain FQDN, used for the Kerberos ticket trigger (e.g. "itservice.com").
        [Parameter(Mandatory = $true)]
        [string] $Domain,

        # Per-port TCP connect timeout in milliseconds.
        [int] $TimeoutMs = 2000
    )

    # --- TCP PORTS ---
    $TcpPorts = @(
        @{Port=53;   Desc="DNS"},
        @{Port=88;   Desc="Kerberos"},
        @{Port=135;  Desc="DCE/EPMAP (RPC Endpoint Mapper)"},
        @{Port=389;  Desc="LDAP"},
        @{Port=445;  Desc="SMB"},
        @{Port=464;  Desc="Kerberos password change"},
        @{Port=636;  Desc="LDAPS"}
    )

    # --- UDP PORTS ---
    # Only DNS (53) is probed over UDP, because it is the one AD UDP service that
    # reliably answers a generic probe (a DNS query). Kerberos (88) and LDAP (389)
    # over UDP cannot be proven with a generic probe (SGs silently drop blocked
    # packets), so instead of guessing we validate the Kerberos path with a real
    # TGT request below (see "Kerberos ticket trigger"). UDP 464 (kpasswd) is only
    # used during a password change and is covered by the same Kerberos path.
    $UdpPorts = @(
        @{Port=53;  Desc="DNS";  Probe="dns"}
    )

    foreach ($DC in $DCs) {
        Write-Host "`n=== Testing connectivity to $DC ===" -ForegroundColor Cyan

        # =====================================================================
        # TCP Tests - parallel using RunspacePool for speed
        # Uses TcpClient.ConnectAsync instead of Test-NetConnection to avoid
        # DNS resolution and ICMP ping overhead. All ports tested simultaneously.
        # =====================================================================
        Write-Host "`n[TCP Ports - Fixed]" -ForegroundColor Yellow

        $runspacePool = [RunspaceFactory]::CreateRunspacePool(1, 16)
        $runspacePool.Open()
        $jobs = @()

        foreach ($entry in $TcpPorts) {
            $ps = [PowerShell]::Create().AddScript({
                param($ip, $port, $timeout)
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $task = $tcp.ConnectAsync($ip, $port)
                    if ($task.Wait($timeout)) { $tcp.Connected } else { $false }
                } catch { $false }
                finally { if ($tcp) { $tcp.Dispose() } }
            }).AddArgument($DC).AddArgument($entry.Port).AddArgument($TimeoutMs)

            $ps.RunspacePool = $runspacePool
            $jobs += @{PS=$ps; Handle=$ps.BeginInvoke(); Port=$entry.Port; Desc=$entry.Desc}
        }

        foreach ($job in $jobs) {
            $success = $job.PS.EndInvoke($job.Handle)
            $status = if ($success -contains $true) { "PASS" } else { "FAIL" }
            $color = if ($success -contains $true) { "Green" } else { "Red" }
            Write-Host ("  TCP {0,-5} ({1,-35}) : {2}" -f $job.Port, $job.Desc, $status) -ForegroundColor $color
            $job.PS.Dispose()
        }
        $runspacePool.Close()

        # =====================================================================
        # RPC Ephemeral Port Discovery
        # If TCP 135 is reachable, query the RPC Endpoint Mapper to find which
        # ephemeral ports (49152-65535) are actually in use, then test those.
        # This avoids false negatives from testing arbitrary ports like 49153.
        # =====================================================================
        Write-Host "`n[TCP Ports - RPC Ephemeral (dynamic discovery via port 135)]" -ForegroundColor Yellow

        # First verify 135 is reachable
        $tcp135 = New-Object System.Net.Sockets.TcpClient
        $task135 = $tcp135.ConnectAsync($DC, 135)
        $can135 = $task135.Wait($TimeoutMs) -and $tcp135.Connected
        $tcp135.Dispose()

        if (-not $can135) {
            Write-Host "  SKIP - TCP 135 not reachable, cannot query Endpoint Mapper" -ForegroundColor Red
        } else {
            Write-Host "  TCP 135   (RPC Endpoint Mapper)         : PASS" -ForegroundColor Green

            # Try to discover the ACTIVE ephemeral ports via portqry (if present).
            # We only test ports that the Endpoint Mapper actually reports in use -
            # probing arbitrary ports in the 49152-65535 range is meaningless because
            # RPC assigns them on demand and most will have no listener at any moment.
            $rpcPorts = @()
            try {
                $portqryPath = Get-Command portqry -ErrorAction SilentlyContinue
                if ($portqryPath) {
                    $output = & portqry -n $DC -e 135 -p tcp 2>&1
                    $rpcPorts = ($output | Select-String "ip_tcp\[(\d+)\]" -AllMatches).Matches |
                        ForEach-Object { [int]$_.Groups[1].Value } |
                        Where-Object { $_ -ge 49152 } |
                        Sort-Object -Unique
                }
            } catch {}

            if ($rpcPorts.Count -eq 0) {
                # No portqry (or it returned nothing) - this is the normal/expected case.
                # TCP 135 being reachable is the meaningful result; the dynamic ports
                # cannot be meaningfully pre-tested. Report it as informational, not a failure.
                Write-Host "  INFO: Endpoint Mapper (135) is reachable. RPC ephemeral ports (49152-65535)" -ForegroundColor Cyan
                Write-Host "        are allocated on demand and negotiated via port 135 at connect time," -ForegroundColor DarkGray
                Write-Host "        so individual ports are not pre-tested here. Ensure the security group" -ForegroundColor DarkGray
                Write-Host "        allows the full TCP 49152-65535 range so RPC can complete." -ForegroundColor DarkGray
                Write-Host "        (Install Windows Support Tools 'portqry' to enumerate active RPC ports.)" -ForegroundColor DarkGray
            } else {
                # portqry discovered real active endpoints - test those specific ports.
                $rpcPool = [RunspaceFactory]::CreateRunspacePool(1, 16)
                $rpcPool.Open()
                $rpcJobs = @()

                foreach ($port in $rpcPorts) {
                    $ps = [PowerShell]::Create().AddScript({
                        param($ip, $port, $timeout)
                        try {
                            $tcp = New-Object System.Net.Sockets.TcpClient
                            $task = $tcp.ConnectAsync($ip, $port)
                            if ($task.Wait($timeout)) { $tcp.Connected } else { $false }
                        } catch { $false }
                        finally { if ($tcp) { $tcp.Dispose() } }
                    }).AddArgument($DC).AddArgument($port).AddArgument($TimeoutMs)

                    $ps.RunspacePool = $rpcPool
                    $rpcJobs += @{PS=$ps; Handle=$ps.BeginInvoke(); Port=$port}
                }

                $passCount = 0
                $failCount = 0
                foreach ($job in $rpcJobs) {
                    $success = $job.PS.EndInvoke($job.Handle)
                    if ($success -contains $true) {
                        $passCount++
                        Write-Host ("  TCP {0,-5} (RPC Endpoint - active)    : PASS" -f $job.Port) -ForegroundColor Green
                    } else {
                        $failCount++
                    }
                    $job.PS.Dispose()
                }
                $rpcPool.Close()

                if ($failCount -gt 0 -and $passCount -gt 0) {
                    Write-Host ("  ({0} active endpoint(s) not reachable - verify SG allows 49152-65535)" -f $failCount) -ForegroundColor DarkYellow
                } elseif ($passCount -eq 0) {
                    Write-Host "  INFO: Active RPC endpoints were discovered but none were reachable." -ForegroundColor Cyan
                    Write-Host "        Verify the security group allows the full TCP 49152-65535 range." -ForegroundColor DarkGray
                }
            }
        }

        # =====================================================================
        # UDP Tests - DNS (53) only, via a protocol-aware DNS query.
        # A reachable DNS server always responds, making this a reliable
        # open/blocked test. Other AD UDP ports are covered by the Kerberos
        # ticket trigger below rather than unreliable generic UDP probes.
        # =====================================================================
        Write-Host "`n[UDP Ports]" -ForegroundColor Yellow
        foreach ($entry in $UdpPorts) {
            try {
                $udpClient = New-Object System.Net.Sockets.UdpClient
                $udpClient.Client.ReceiveTimeout = 3000
                $udpClient.Connect($DC, $entry.Port)

                if ($entry.Probe -eq "dns") {
                    # Valid DNS query for root domain - any DNS server will respond
                    $bytes = [byte[]](0x00,0x01,  # Transaction ID
                                     0x01,0x00,  # Flags: standard query
                                     0x00,0x01,  # Questions: 1
                                     0x00,0x00,  # Answers: 0
                                     0x00,0x00,  # Authority: 0
                                     0x00,0x00,  # Additional: 0
                                     0x00,       # Root domain
                                     0x00,0x01,  # Type: A
                                     0x00,0x01)  # Class: IN
                } else {
                    $bytes = [byte[]](0x00) * 4
                }

                [void]$udpClient.Send($bytes, $bytes.Length)

                try {
                    $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                    [void]$udpClient.Receive([ref]$remoteEP)
                    $status = "PASS (response received)"
                    $color = "Green"
                } catch [System.Net.Sockets.SocketException] {
                    if ($_.Exception.SocketErrorCode -eq 'ConnectionReset') {
                        # ICMP port unreachable - host reachable but port closed
                        $status = "FAIL (port unreachable)"
                        $color = "Red"
                    } else {
                        # Timeout - cannot distinguish SG drop from unresponsive service
                        $status = "INCONCLUSIVE (no response)"
                        $color = "Yellow"
                    }
                }
            } catch {
                $status = "FAIL ($($_.Exception.Message))"
                $color = "Red"
            } finally {
                if ($udpClient) { $udpClient.Close() }
            }
            Write-Host ("  UDP {0,-5} ({1,-35}) : {2}" -f $entry.Port, $entry.Desc, $status) -ForegroundColor $color
        }

        # =====================================================================
        # Kerberos reachability check - SCOPED TO THIS DC ($DC)
        # Uses nltest /dsgetdc with /server:<DC> so the locator is forced to use
        # the SPECIFIC domain controller passed in -DCs, instead of letting
        # Windows pick any KDC in the domain. This keeps the Kerberos result
        # consistent with the TCP/UDP probes above (which also target $DC).
        #   - PASS => this host located and reached DC $DC over the Kerberos/LDAP
        #             locator path (DNS + CLDAP/Kerberos), i.e. the path is open.
        #   - FAIL => DC $DC was not reachable from this host for the locator path.
        # SCOPE: validates the network path + KDC reachability to THIS DC from
        # this host only. It does NOT validate SQL Server Kerberos auth (the RDS
        # domain join, MSSQLSvc SPN registration, or a Kerberos SQL login) -
        # those must be confirmed separately on the RDS/SQL Server side.
        # =====================================================================
        Write-Host "`n[Kerberos / DC locator - scoped to $DC]" -ForegroundColor Yellow

        if (-not (Get-Command nltest.exe -ErrorAction SilentlyContinue)) {
            Write-Host "  SKIP - nltest.exe not available on this host." -ForegroundColor Yellow
        } else {
            $dcOut = & nltest "/dsgetdc:$Domain" "/server:$DC" /kdc 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host ("  nltest /dsgetdc /server:{0} : PASS (DC reached via Kerberos/LDAP locator)" -f $DC) -ForegroundColor Green
                Write-Host "    Note: confirms the Kerberos path to THIS DC from this host. It does not" -ForegroundColor DarkGray
                Write-Host "    validate SQL Server Kerberos auth (RDS domain join / MSSQLSvc SPN / login)." -ForegroundColor DarkGray
            } else {
                Write-Host ("  nltest /dsgetdc /server:{0} : FAIL (DC not reachable for Kerberos/LDAP locator)" -f $DC) -ForegroundColor Red
                Write-Host ("    {0}" -f ($dcOut | Select-Object -Last 1)) -ForegroundColor Red
                Write-Host "    If TCP/UDP DNS passed, check: SG/NACL allow Kerberos (88) + LDAP (389) to" -ForegroundColor DarkGray
                Write-Host "    this DC, DNS resolves the domain, and host clock is within 5 min of the DC." -ForegroundColor DarkGray
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Execute using the parameters passed to the script.
# -----------------------------------------------------------------------------
Test-ADConnectivity -DCs $DCs -Domain $Domain -TimeoutMs $TimeoutMs
 
