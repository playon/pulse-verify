#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-deployment network check for a PlayOn / Pixellot VPU.
.DESCRIPTION
    Run from any Windows laptop or Mac plugged into the network segment (VLAN /
    switch port) the VPU will use. On Windows it runs under the built-in
    PowerShell 5.1; on macOS under the PowerShell 7 bundled in the Mac zip. Checks DNS, the required TCP/UDP egress, and TLS
    interception against the list in endpoints.json, then writes a pass/fail
    report (HTML + JSON) the venue's IT team can send back to PlayOn.

    The probes are ported from playon/pulse Pulse.Web/scripts so a pass here
    means the same thing as a pass in Pulse on the VPU. Same PowerShell 5.1
    rules apply (see pulse CLAUDE.md): ASCII only, explicit delegate casts,
    pinned SslProtocols, [pscustomobject] rows.
.PARAMETER EndpointsPath
    Path to endpoints.json. Defaults to the copy next to this script.
.PARAMETER OutDir
    Where to write the report (.html and .json). Defaults to a reports
    folder next to this script. The .log always goes in a logs folder next
    to this script.
.PARAMETER Venue
    Optional venue / school name printed on the report. Never asked for.
.PARAMETER PixellotId
    Optional Pixellot ID from the unit's label. Never asked for; on a
    Pixellot itself it defaults to the computer name.
.PARAMETER SkipQuestions
    Skip the pre-test questions (for scripted or remote runs). The report
    records the answers as "not asked". The speed test still runs unless
    -SkipSpeedTest is also passed.
.PARAMETER SkipSpeedTest
    Skip the speed test without asking. The report notes that speed was not
    measured.
.EXAMPLE
    .\Test-PulseVerify.ps1 -Venue "Lincoln High Gym"
#>
[CmdletBinding()]
param(
    [string]$EndpointsPath = '',
    [string]$OutDir = '',
    [string]$Venue = '',
    [string]$PixellotId = '',
    [switch]$SkipQuestions,
    [switch]$SkipSpeedTest
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.1.0'
$script:LogPath = $null

# ---------------------------------------------------------------- helpers

function Write-Log([string]$Message) {
    # Plain-text log in the logs folder, for support to review. Never let a
    # logging failure stop the check.
    if (-not $script:LogPath) { return }
    try {
        $line = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') + '  ' + $Message + "`r`n"
        [System.IO.File]::AppendAllText($script:LogPath, $line, (New-Object System.Text.UTF8Encoding($false)))
    }
    catch { }
}

# Console text wraps at 78 columns so it reads in a default cmd.exe window
# (80 wide) without lines breaking mid-word.
function Write-Wrapped([string]$Text, [string]$Indent = '', [string]$Color = '', [string]$FirstIndent = '') {
    # FirstIndent gives bullets a hanging indent: "  - " then "    ". A
    # [string] parameter turns $null into '', so test whether it was passed.
    if (-not $PSBoundParameters.ContainsKey('FirstIndent')) { $FirstIndent = $Indent }
    $lead = $FirstIndent
    $line = ''
    foreach ($word in ($Text -split '\s+' | Where-Object { $_ })) {
        if ($line.Length -gt 0 -and ($lead.Length + $line.Length + 1 + $word.Length) -gt 78) {
            if ($Color) { Write-Host ($lead + $line) -ForegroundColor $Color } else { Write-Host ($lead + $line) }
            $lead = $Indent
            $line = $word
        }
        elseif ($line.Length -gt 0) { $line += ' ' + $word }
        else { $line = $word }
    }
    if ($line) {
        if ($Color) { Write-Host ($lead + $line) -ForegroundColor $Color } else { Write-Host ($lead + $line) }
    }
}

# A titled rule between phases ("-- Title -----", 78 wide). The rule is
# dim so it separates without competing with the text; the blank lines
# around it give each phase room.
function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host '-- ' -ForegroundColor DarkGray -NoNewline
    Write-Host $Title -ForegroundColor Cyan -NoNewline
    Write-Host (' ' + ('-' * [Math]::Max(3, 74 - $Title.Length))) -ForegroundColor DarkGray
    Write-Host ''
}

function Resolve-OutDir([string]$Requested, [string]$Fallback) {
    # Clean up what a launcher may pass: cmd's "%~dp0" ends in a backslash
    # that escapes the closing quote, leaving a literal " on the end, which
    # WriteAllText rejects as "Illegal characters in path".
    $candidates = @()
    if ($Requested) { $candidates += $Requested.Trim().Trim('"').Trim() }
    if ($Fallback)  { $candidates += $Fallback }
    $candidates += [System.IO.Path]::GetTempPath()
    foreach ($c in $candidates) {
        if (-not $c) { continue }
        try {
            $full = [System.IO.Path]::GetFullPath($c)
            if (-not (Test-Path -LiteralPath $full -PathType Container)) { continue }
            $probe = Join-Path $full ('.write-test-' + [guid]::NewGuid().ToString('N'))
            [System.IO.File]::WriteAllText($probe, 'x')
            Remove-Item -LiteralPath $probe -Force
            return $full
        }
        catch { continue }
    }
    throw 'No writable folder found for the report.'
}

function Get-IPv4([string]$HostName) {
    [System.Net.Dns]::GetHostAddresses($HostName) |
        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
        Select-Object -First 1
}

function New-Result($Category, $Target, $Purpose, $Status, $Detail, $Fix, $Ip = $null, $Outcome = $null) {
    # ip and outcome are evidence for the firewall admin: which address was
    # tried, and whether it was dropped, rejected or answered. They go in the
    # report next to the failure and into the JSON for support.
    [pscustomobject]@{
        category = $Category
        target   = $Target
        purpose  = $Purpose
        status   = $Status      # pass | fail | warn
        detail   = $Detail
        fix      = $Fix
        ip       = $Ip
        outcome  = $Outcome
    }
}

# ---------------------------------------------------------------- DNS

function Test-Dns($Entry) {
    # Lookups go through this computer's resolver (the venue's DNS), which the
    # detail names, since the Pixellot itself defaults to 8.8.8.8.
    $via = if ($script:Resolver) { " via $($script:Resolver)" } else { '' }
    $fix = "Allow DNS lookups of $($Entry.domain). If the network uses DNS filtering (Cisco Umbrella, Lightspeed, Securly and similar), allow $($Entry.domain) there."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $ip = Get-IPv4 $Entry.host
        $sw.Stop()
        $ms = if ($sw.ElapsedMilliseconds -gt 0) { "$($sw.ElapsedMilliseconds) ms" } else { 'cached' }
        if ($ip) {
            return New-Result 'DNS' $Entry.host $Entry.purpose 'pass' ("Resolved to {0}{1} ({2})" -f $ip, $via, $ms) $null ([string]$ip) 'resolved'
        }
        return New-Result 'DNS' $Entry.host $Entry.purpose 'fail' "No IPv4 address returned$via" $fix $null 'no-address'
    }
    catch {
        $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        return New-Result 'DNS' $Entry.host $Entry.purpose 'fail' "Name not found$via ($msg). The name may be blocked by DNS filtering." $fix $null 'not-found'
    }
}

function Resolve-HostAddresses([string]$HostName) {
    # Every IPv4 address for a host, for IT teams whose firewall takes IPs
    # rather than domain names. Resolve-DnsName (Windows) also returns the
    # CNAME chain, which shows when a host sits on a CDN or cloud load
    # balancer and its addresses will change; elsewhere fall back to .NET.
    $r = [pscustomobject]@{ host = $HostName; ipv4 = @(); aliases = @(); error = $null }
    try {
        if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
            $recs = @(Resolve-DnsName -Name $HostName -Type A -DnsOnly -ErrorAction Stop)
            $r.aliases = @($recs | Where-Object { $_.Type -eq 'CNAME' } | ForEach-Object { [string]$_.NameHost })
            $r.ipv4 = @($recs | Where-Object { $_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
        }
        else {
            $r.ipv4 = @([System.Net.Dns]::GetHostAddresses($HostName) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { [string]$_ })
        }
        $r.ipv4 = @($r.ipv4 | Sort-Object { [version]$_ } -Unique)
        if (-not $r.ipv4) { $r.error = 'No IPv4 address returned' }
    }
    catch {
        $r.error = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
    }
    $r
}

function Get-RuleDomains($Rules) {
    # The wildcard domains named in the rules, in rule order.
    @($Rules | ForEach-Object { $_.destination -split ',\s*' } | Where-Object { $_.StartsWith('*.') } | Select-Object -Unique)
}

function Get-DomainAddresses($Endpoints) {
    # The required domains are wildcards, which can't be looked up, so this
    # resolves each host the probes use under each domain. Hosts outside the
    # required domains (8.8.8.8, the public RTMP stand-in) are left out.
    $hosts = @(@($Endpoints.dns) + @($Endpoints.ports) + @($Endpoints.tls) |
        ForEach-Object { $_.host } | Where-Object { $_ -notmatch '^[\d.]+$' } | Select-Object -Unique)
    foreach ($d in (Get-RuleDomains $Endpoints.requirements.rules)) {
        $suffix = $d -replace '^\*\.', ''
        $mine = @($hosts | Where-Object { $_ -eq $suffix -or $_.EndsWith(".$suffix") } | Sort-Object)
        $rows = foreach ($hn in $mine) {
            $a = Resolve-HostAddresses $hn
            Write-Log ("ADDR  {0,-45} {1}{2}" -f $hn, $(if ($a.error) { $a.error } else { $a.ipv4 -join ', ' }), $(if ($a.aliases) { ' (alias of ' + ($a.aliases -join ' -> ') + ')' } else { '' }))
            $a
        }
        [pscustomobject]@{ domain = $d; hosts = @($rows) }
    }
}

# ---------------------------------------------------------------- ports

function Test-TcpConnect([string]$HostName, [int]$Port, [switch]$KeepOpen) {
    # Tells a silent drop from an active reject: a firewall admin looks for a
    # different rule in each case. Connects to the resolved IP so the report
    # can name the address that was tried. With -KeepOpen a connected socket
    # is returned in .client for the caller to use and close.
    $r = @{ outcome = 'error'; ip = $null; ms = $null; message = $null; client = $null }
    try { $addr = Get-IPv4 $HostName } catch { $addr = $null }
    if (-not $addr) { $r.outcome = 'no-dns'; return $r }
    $r.ip = [string]$addr
    $tcp = New-Object System.Net.Sockets.TcpClient
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $ar = $tcp.BeginConnect($addr, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(4000, $false)) { $r.outcome = 'timeout'; return $r }
        try {
            $null = $tcp.EndConnect($ar)
            $r.outcome = 'connected'
            if ($KeepOpen) { $r.client = $tcp }
        }
        catch {
            $se = $_.Exception
            while ($se -and -not ($se -is [System.Net.Sockets.SocketException])) { $se = $se.InnerException }
            # SocketErrorCode, not ErrorCode: the enum is the same on every
            # platform (Windows 10061 = ConnectionRefused = a TCP reset).
            $code = if ($se) { [string]$se.SocketErrorCode } else { '' }
            $r.outcome = switch ($code) {
                'ConnectionRefused'  { 'refused' }
                'HostUnreachable'    { 'unreachable' }
                'NetworkUnreachable' { 'unreachable' }
                default              { 'error' }
            }
            $r.message = $_.Exception.Message
        }
        return $r
    }
    finally {
        $sw.Stop(); $r.ms = $sw.ElapsedMilliseconds
        if (-not $r.client) { $tcp.Close() }
    }
}

function Test-UdpReply([string]$HostName, [int]$Port, [byte[]]$Payload, [int]$TimeoutMs) {
    # prod-echo answers on 123/443/2088 by echoing the datagram back, so a
    # reply is REQUIRED to pass. A silent timeout is the most common school
    # firewall block mode; treating it as "open|filtered" false-passes.
    $r = @{ outcome = 'no-reply'; ip = $null }
    try { $addr = Get-IPv4 $HostName } catch { $addr = $null }
    if (-not $addr) { $r.outcome = 'no-dns'; return $r }
    $r.ip = [string]$addr
    $ep = New-Object System.Net.IPEndPoint($addr, $Port)
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Client.SendTimeout = $TimeoutMs
        try {
            $null = $udp.Send($Payload, $Payload.Length, $ep)
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $resp = $udp.Receive([ref]$remote)
            if ($resp.Length -gt 0) { $r.outcome = 'reply'; return $r }
        }
        catch [System.Net.Sockets.SocketException] {
            # ICMP port unreachable surfaces as ConnectionReset on Windows
            # (10054) and ConnectionRefused elsewhere: a definitive reject.
            $se = $_.Exception
            while ($se -and -not ($se -is [System.Net.Sockets.SocketException])) { $se = $se.InnerException }
            $sec = if ($se) { [string]$se.SocketErrorCode } else { '' }
            if ($sec -eq 'ConnectionReset' -or $sec -eq 'ConnectionRefused') { $r.outcome = 'rejected'; return $r }
        }
        finally { $udp.Close() }
    }
    return $r
}

function Get-PortDetail([string]$Protocol, $R, [string]$HostName, [int]$TimeoutS) {
    switch ($R.outcome) {
        'connected'   { return "Connected to $($R.ip) in $($R.ms) ms" }
        'reply'       { return "Reply received from $($R.ip)" }
        'timeout'     { return "No response from $($R.ip) within $TimeoutS s: the traffic was silently dropped. Look for a deny or drop rule." }
        'no-reply'    { return "No reply from $($R.ip) after 2 tries: the traffic was silently dropped. Look for a deny or drop rule." }
        'refused'     { return "Rejected by $($R.ip) with a TCP reset: something actively refused the connection. Look for a deny rule that sends resets." }
        'rejected'    { return "Rejected: $($R.ip) answered with ICMP port unreachable. Look for a reject rule." }
        'unreachable' { return "No route to $($R.ip) (ICMP host or network unreachable)." }
        'no-dns'      { return "Could not look up $HostName, so nothing was sent. See the DNS results." }
        default       { return "Connection error to $($R.ip): $($R.message)" }
    }
}

function Test-Port($Entry) {
    $label = "{0} {1} -> {2}" -f $Entry.protocol, $Entry.port, $Entry.host
    $fix = if ($Entry.rule) { $Entry.rule } else { "Allow outbound $($Entry.protocol) $($Entry.port) to $($Entry.domain)." }
    try {
        switch ($Entry.probe) {
            'connect' { $r = Test-TcpConnect $Entry.host ([int]$Entry.port); $timeout = 4 }
            'ntp' {
                # Real 48-byte NTP v3 client request so NTP-aware middleboxes
                # treat it as NTP. Byte 0 = 0x1B (LI=0, VN=3, Mode=3).
                $pkt = New-Object byte[] 48
                $pkt[0] = 0x1B
                $r = Test-UdpReply $Entry.host ([int]$Entry.port) $pkt 3000
            }
            'dns' {
                # Standard A query for pixellot.tv. The laptop's own lookups go
                # through the venue resolver; the Pixellot defaults to 8.8.8.8,
                # so this proves that path separately.
                $pkt = [byte[]](0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
                    7) + [System.Text.Encoding]::ASCII.GetBytes('pixellot') + [byte[]](2) +
                    [System.Text.Encoding]::ASCII.GetBytes('tv') + [byte[]](0, 0x00,0x01, 0x00,0x01)
                $r = Test-UdpReply $Entry.host ([int]$Entry.port) ([byte[]]$pkt) 3000
            }
            'echo' {
                $pkt = [System.Text.Encoding]::ASCII.GetBytes("pulse-verify UDP $($Entry.port)")
                $r = Test-UdpReply $Entry.host ([int]$Entry.port) $pkt 2000
            }
            default { throw "Unknown probe '$($Entry.probe)'" }
        }
    }
    catch {
        return New-Result 'Port' $label $Entry.purpose 'fail' $_.Exception.Message $fix
    }
    $detail = Get-PortDetail $Entry.protocol $r $Entry.host 4
    if ($r.outcome -eq 'connected' -or $r.outcome -eq 'reply') {
        return New-Result 'Port' $label $Entry.purpose 'pass' $detail $null $r.ip $r.outcome
    }
    return New-Result 'Port' $label $Entry.purpose 'fail' $detail $fix $r.ip $r.outcome
}

# ---------------------------------------------------------------- TLS

# Names the inspection product from the substituted certificate, so the
# admin knows which console to open. Matched against issuer and root.
$CertVendorPatterns = @(
    @{ pattern = 'fortinet|fortigate';            name = 'Fortinet FortiGate' }
    @{ pattern = 'palo ?alto';                    name = 'Palo Alto Networks' }
    @{ pattern = 'sophos';                        name = 'Sophos' }
    @{ pattern = 'lightspeed';                    name = 'Lightspeed Systems' }
    @{ pattern = 'securly';                       name = 'Securly' }
    @{ pattern = 'goguardian';                    name = 'GoGuardian' }
    @{ pattern = 'zscaler';                       name = 'Zscaler' }
    @{ pattern = 'umbrella|opendns';              name = 'Cisco Umbrella' }
    @{ pattern = 'meraki';                        name = 'Cisco Meraki' }
    @{ pattern = 'iboss';                         name = 'iboss' }
    @{ pattern = 'contentkeeper';                 name = 'ContentKeeper' }
    @{ pattern = 'barracuda';                     name = 'Barracuda' }
    @{ pattern = 'netsweeper';                    name = 'Netsweeper' }
    @{ pattern = 'sonicwall';                     name = 'SonicWall' }
    @{ pattern = 'watchguard';                    name = 'WatchGuard' }
    @{ pattern = 'smoothwall';                    name = 'Smoothwall' }
    @{ pattern = 'linewize|familyzone';           name = 'Linewize' }
    @{ pattern = 'blocksi';                       name = 'Blocksi' }
    @{ pattern = 'deledao';                       name = 'Deledao' }
    @{ pattern = 'forcepoint|websense';           name = 'Forcepoint' }
    @{ pattern = 'untangle|arista edge';          name = 'Untangle / Arista Edge' }
    @{ pattern = 'check ?point';                  name = 'Check Point' }
)

function Test-Tls($Entry) {
    # Accept any cert during the handshake, then validate it ourselves, so a
    # firewall's substituted cert is captured and named instead of just
    # aborting. Ported from Test-TlsInspection.ps1 (Kent SD, 2026-07).
    # TODO: port Get-FilterBlockSignal (block-page vendor detection) for
    # hosts whose handshake is reset outright.
    $exempt = "Exempt $($Entry.domain) from SSL/TLS inspection (decryption)."
    $tcp = $null; $ssl = $null
    $script:PresentedCert = $null
    # One connection: classify how it connected, then handshake on the same
    # socket. A separate connect-and-close first looks like a port scan, and
    # api.singular.live's front end stalled the follow-up handshake for it.
    $conn = Test-TcpConnect $Entry.host 443 -KeepOpen
    if ($conn.outcome -ne 'connected') {
        return New-Result 'TLS' $Entry.host $Entry.purpose 'fail' (Get-PortDetail 'TCP' $conn $Entry.host 4) `
            "Allow outbound TCP 443 to $($Entry.domain)." $conn.ip $conn.outcome
    }
    $tcp = $conn.client
    try {

        # Delegate cast is REQUIRED on Windows PowerShell 5.1.
        $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($s, $cert, $chain, $errors)
            if ($cert) {
                $script:PresentedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
            }
            return $true
        }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
        $ssl.ReadTimeout = 6000
        $ssl.WriteTimeout = 6000
        # Pin protocols: 5.1's parameterless overload defaults to SSL3/TLS 1.0.
        $protocols = [System.Security.Authentication.SslProtocols]'Tls, Tls11, Tls12'
        $ssl.AuthenticateAsClient($Entry.host, $null, $protocols, $false)

        $cert = $script:PresentedCert
        if (-not $cert) {
            return New-Result 'TLS' $Entry.host $Entry.purpose 'fail' "No certificate presented by $($conn.ip)." `
                "Check for a proxy or filter on TCP 443 to $($Entry.domain). $exempt" $conn.ip 'no-cert'
        }
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $trusted = $chain.Build($cert)
        $nt = [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName
        $issuer = $cert.GetNameInfo($nt, $true)
        if ($trusted) {
            return New-Result 'TLS' $Entry.host $Entry.purpose 'pass' "Trusted certificate issued by $issuer" $null $conn.ip 'trusted'
        }
        # Untrusted: almost always a firewall decrypting the traffic and
        # re-signing it with its own CA. Give the admin what they need to
        # find that CA: subject, issuer, root, thumbprint, likely vendor.
        $root = $null
        if ($chain.ChainElements.Count -gt 0) {
            $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.GetNameInfo($nt, $false)
        }
        $haystack = ("$($cert.Issuer) $root").ToLower()
        $vendor = $null
        foreach ($v in $CertVendorPatterns) { if ($haystack -match $v.pattern) { $vendor = $v.name; break } }
        $who = if ($vendor) { "likely $vendor SSL inspection" } else { 'SSL inspection by a firewall or web filter' }
        $detail = ("Certificate was replaced ({0}). Presented: subject '{1}', issuer '{2}', root '{3}', SHA-1 {4}, from {5}." -f
            $who, $cert.GetNameInfo($nt, $false), $issuer, $root, $cert.Thumbprint, $conn.ip)
        return New-Result 'TLS' $Entry.host $Entry.purpose 'fail' $detail $exempt $conn.ip 'intercepted'
    }
    catch {
        return New-Result 'TLS' $Entry.host $Entry.purpose 'fail' `
            ("Connection to $($conn.ip) was cut during the TLS handshake ($($_.Exception.Message)). A web filter is likely blocking $($Entry.host) by name.") `
            "Allow $($Entry.domain) in the web filter. $exempt" $conn.ip 'reset'
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Close() }
    }
}

# ---------------------------------------------------------------- speed

function Measure-Throughput($Cfg, [string]$Direction) {
    # Single-stream, time-boxed transfer. One stream can under-read a fast
    # high-latency link, but it is plenty to answer "is it at least 10 Mbps",
    # which is the documented minimum. Returns Mbps.
    $limit = [double]$Cfg.seconds
    $buffer = New-Object byte[] 65536
    $bytes = [long]0
    $sw = New-Object System.Diagnostics.Stopwatch
    $req = $null; $resp = $null; $stream = $null
    try {
        if ($Direction -eq 'Download') {
            $req = [System.Net.HttpWebRequest]::Create([string]$Cfg.downloadUrl)
            $req.Timeout = 15000
            $req.ReadWriteTimeout = 15000
            $resp = $req.GetResponse()
            $stream = $resp.GetResponseStream()
            $sw.Start()   # after headers, so connection setup isn't counted
            while ($sw.Elapsed.TotalSeconds -lt $limit) {
                $n = $stream.Read($buffer, 0, $buffer.Length)
                if ($n -le 0) { break }
                $bytes += $n
            }
        }
        else {
            # Fixed 12 MB, timed until the server's response: a write returns
            # once the OS has buffered the data, not when it was sent, so
            # stopping the clock at the last write over-reads badly (measured
            # 664 Mbps on a 65 Mbps uplink). 12 MB takes about 10 s at the
            # 10 Mbps minimum. Give up at 2x the time limit; by then the link is
            # clearly below the minimum, and the rate is reported from what
            # was written so far.
            $total = [long]12MB
            $req = [System.Net.HttpWebRequest]::Create([string]$Cfg.uploadUrl)
            $req.Method = 'POST'
            $req.ContentType = 'application/octet-stream'
            $req.ContentLength = $total
            $req.AllowWriteStreamBuffering = $false
            $req.Timeout = 30000
            $req.ReadWriteTimeout = 30000
            $stream = $req.GetRequestStream()
            $sw.Start()
            while ($bytes -lt $total -and $sw.Elapsed.TotalSeconds -lt (2 * $limit)) {
                $n = [int][Math]::Min($buffer.Length, $total - $bytes)
                $stream.Write($buffer, 0, $n)
                $bytes += $n
            }
            if ($bytes -ge $total) {
                $stream.Close(); $stream = $null
                $resp = $req.GetResponse()
            }
        }
        $sw.Stop()
    }
    finally {
        if ($sw.IsRunning) { $sw.Stop() }
        if ($stream) { try { $stream.Close() } catch { } }
        if ($resp) { $resp.Close() }
        if ($req -and $Direction -eq 'Upload' -and -not $resp) { $req.Abort() }
    }
    if ($sw.Elapsed.TotalSeconds -le 0 -or $bytes -le 0) { throw 'No data transferred' }
    return [Math]::Round(($bytes * 8) / $sw.Elapsed.TotalSeconds / 1e6, 1)
}

function Test-Speed($Cfg, [string]$Direction) {
    $min = [double]$Cfg.minMbps
    $label = "$Direction speed"
    try {
        $mbps = Measure-Throughput $Cfg $Direction
    }
    catch {
        # The speed host itself may be filtered. That says nothing about the
        # Pixellot's own traffic, so warn rather than fail.
        $why = $_.Exception.Message
        $fix = 'Allow speed.cloudflare.com for this test, or measure upload and download another way.'
        if ($why -match '\(429\)') { $why = 'the speed test site is limiting requests from this network. Try again in a few minutes.'; $fix = 'Run the check again in a few minutes.' }
        elseif ($why -match '\((40[0-9])\)') { $why = "the speed test site refused the request (HTTP $($Matches[1]))." }
        elseif ($why -match 'could not be resolved|not known|No such host') { $why = 'speed.cloudflare.com could not be looked up.' }
        return New-Result 'Speed' $label "At least $min Mbps" 'warn' ("Could not measure: " + $why) `
            $fix
    }
    if ($mbps -ge $min) {
        return New-Result 'Speed' $label "At least $min Mbps" 'pass' "$mbps Mbps" $null
    }
    return New-Result 'Speed' $label "At least $min Mbps" 'fail' "$mbps Mbps (below $min Mbps)" `
        "The Pixellot needs at least $min Mbps $($Direction.ToLower()). Remove bandwidth caps or rate limits for it, or increase the connection's capacity."
}

# ---------------------------------------------------------------- context

function Test-IsMacOS {
    # $IsMacOS exists only in PowerShell 6+; on Windows PowerShell 5.1 it is
    # unset, so read it without assuming it is there.
    return [bool](Get-Variable -Name IsMacOS -ValueOnly -ErrorAction SilentlyContinue)
}

function Get-MacUplink {
    # macOS counterpart of the Get-NetRoute / Get-NetAdapter lookups below:
    # the interface holding the default route, using built-in tools only
    # (route, ifconfig, ipconfig, networksetup, scutil). VPN tunnels are
    # skipped so a VPN doesn't hide the real uplink, matching the Windows
    # view. Returns $null if there is no uplink.
    $vpn = '^(utun|ipsec|ppp|gif|stf|tun|tap)'
    $dev = $null
    $m = @(& /sbin/route -n get default 2>$null) | Select-String -Pattern '^\s*interface:\s*(\S+)' | Select-Object -First 1
    if ($m) { $dev = $m.Matches[0].Groups[1].Value }
    if (-not $dev -or $dev -match $vpn) {
        # Next best: the first non-VPN interface in the system's service order.
        $dev = $null
        $nwi = @(& /usr/sbin/scutil --nwi 2>$null) | Select-String -Pattern '^Network interfaces:\s*(.+)$' | Select-Object -First 1
        if ($nwi) { $dev = @($nwi.Matches[0].Groups[1].Value -split '\s+' | Where-Object { $_ -and $_ -notmatch $vpn }) | Select-Object -First 1 }
    }
    if (-not $dev) { return $null }

    $u = [ordered]@{ device = $dev; port = $null; mac = $null; ip = $null; mask = $null; gateway = $null; dns = @(); dhcp = $false; wifi = $false }

    $g = @(& /sbin/route -n get -ifscope $dev default 2>$null) | Select-String -Pattern '^\s*gateway:\s*(\S+)' | Select-Object -First 1
    if ($g) { $u.gateway = $g.Matches[0].Groups[1].Value }

    # ifconfig prints the mask as hex (0xffffff00); a link-local 169.254
    # address is used only if there is nothing else.
    $inet = @()
    foreach ($line in @(& /sbin/ifconfig $dev 2>$null)) {
        if ($line -match '^\s*ether\s+(\S+)') { $u.mac = $Matches[1] }
        elseif ($line -match '^\s*inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]{8})') {
            $hex = $Matches[2]
            $inet += [pscustomobject]@{ ip = $Matches[1]; mask = ((0..3 | ForEach-Object { [Convert]::ToInt32($hex.Substring($_ * 2, 2), 16) }) -join '.') }
        }
    }
    $pick = $inet | Where-Object { -not $_.ip.StartsWith('169.254.') } | Select-Object -First 1
    if (-not $pick) { $pick = $inet | Select-Object -First 1 }
    if ($pick) { $u.ip = $pick.ip; $u.mask = $pick.mask }

    # A DHCP lease means DHCP; an address without one is static.
    $packet = @(& /usr/sbin/ipconfig getpacket $dev 2>$null)
    $u.dhcp = ($LASTEXITCODE -eq 0 -and $packet.Count -gt 0)

    # The friendly name ("Wi-Fi", "USB 10/100/1000 LAN") is the hardware
    # port. Its listing also has the real MAC: macOS hides it from ifconfig
    # and .NET in some processes (pwsh among them), which then report the
    # placeholder 02:00:00:00:00:00.
    $port = $null; $hwMac = $null; $found = $false
    foreach ($line in @(& /usr/sbin/networksetup -listallhardwareports 2>$null)) {
        if ($line -match '^Hardware Port:\s*(.+?)\s*$') { if ($found) { break }; $port = $Matches[1]; $hwMac = $null }
        elseif ($line -match '^Device:\s*(\S+)\s*$') { $found = ($Matches[1] -eq $dev) }
        elseif ($line -match '^Ethernet Address:\s*(\S+)') { $hwMac = $Matches[1]; if ($found) { break } }
    }
    if ($found) {
        $u.port = $port
        if ((-not $u.mac -or $u.mac -eq '02:00:00:00:00:00') -and $hwMac -and $hwMac -ne 'N/A') { $u.mac = $hwMac }
    }
    $u.wifi = ($u.port -match 'Wi-Fi|AirPort')

    # The uplink's own DNS servers are in its scoped resolver; the first
    # unscoped resolver can belong to a VPN.
    $scoped = $false; $ns = @()
    foreach ($line in @(& /usr/sbin/scutil --dns 2>$null)) {
        if ($line -match 'for scoped queries') { $scoped = $true; continue }
        if (-not $scoped) { continue }
        if ($line -match '^resolver #') { $ns = @(); continue }
        if ($line -match 'nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)\s*$') { $ns += $Matches[1]; continue }
        if ($line -match 'if_index\s*:\s*\d+\s*\((\S+)\)' -and $Matches[1] -eq $dev) { $u.dns = @($ns); break }
    }
    return [pscustomobject]$u
}

function Get-NetContext {
    # Record where the test ran from, so a pass from guest Wi-Fi isn't
    # mistaken for a pass from the VPU's VLAN.
    $ctx = [ordered]@{ computer = [Environment]::MachineName; connection = $null; localIp = $null; gateway = $null; dns = $null; publicIp = $null }
    if (Test-IsMacOS) {
        try {
            $u = Get-MacUplink
            if ($u) {
                $ctx.connection = if ($u.wifi) { 'Wi-Fi' } else { 'Wired' }
                $ctx.gateway = $u.gateway
                $ctx.localIp = $u.ip
                $ctx.dns = $u.dns -join ', '
            }
        }
        catch { Write-Log "Network context unavailable: $($_.Exception.Message)" }
    }
    else {
        try {
            $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
                Sort-Object RouteMetric | Select-Object -First 1
            if ($route) {
                # Wi-Fi is rarely the Pixellot's segment, so flag it. NdisPhysicalMedium 9 = Native 802.11.
                $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
                if ($adapter) {
                    $ctx.connection = if ($adapter.NdisPhysicalMedium -eq 9 -or $adapter.PhysicalMediaType -match '802\.11') { 'Wi-Fi' } else { 'Wired' }
                }
                $ctx.gateway = $route.NextHop
                $ctx.localIp = (Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
                    Select-Object -First 1).IPAddress
                $ctx.dns = ((Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses) -join ', '
            }
        }
        catch { }   # no NetTCPIP module (Linux, or a stripped-down Windows): leave nulls
    }
    try {
        $wc = New-Object System.Net.WebClient
        $ctx.publicIp = $wc.DownloadString('https://api.ipify.org').Trim()
    }
    catch { }
    return [pscustomobject]$ctx
}

function ConvertTo-SubnetMask([int]$PrefixLength) {
    $bits = ('1' * $PrefixLength).PadRight(32, '0')
    return (0..3 | ForEach-Object { [Convert]::ToInt32($bits.Substring($_ * 8, 8), 2) }) -join '.'
}

function Get-IpConfig {
    # The uplink only: the adapter holding the default route. Camera NICs,
    # VPNs and virtual adapters are left out on purpose. Returns a list (0 or
    # 1 rows) so a future multi-adapter view needs no consumer changes.
    # Windows cmdlets, or built-in tools on macOS (Get-MacUplink); returns an
    # empty list elsewhere.
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        if (Test-IsMacOS) {
            $u = Get-MacUplink
            if (-not $u -or -not $u.gateway) { Write-Log 'No adapter has a default gateway'; return @() }
            $rows.Add([pscustomobject]@{
                adapter    = if ($u.port) { "$($u.port) ($($u.device))" } else { $u.device }
                uplink     = $true
                mac        = $u.mac
                addressing = if ($u.dhcp) { 'DHCP' } elseif ($u.ip) { 'Static' } else { $null }
                ipAddress  = $u.ip
                subnetMask = $u.mask
                gateway    = $u.gateway
                dns1       = if ($u.dns.Count -ge 1) { $u.dns[0] } else { $null }
                dns2       = if ($u.dns.Count -ge 2) { $u.dns[1] } else { $null }
            })
            return ,$rows.ToArray()
        }
        $uplinkIdx = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
            Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
        if (-not $uplinkIdx) { Write-Log 'No adapter has a default gateway'; return @() }
        $adapters = @(Get-NetAdapter -InterfaceIndex $uplinkIdx -ErrorAction Stop)
        foreach ($a in $adapters) {
            $ips = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
            $ip = $ips | Where-Object { -not $_.IPAddress.StartsWith('169.254.') } | Select-Object -First 1
            if (-not $ip) { $ip = $ips | Select-Object -First 1 }
            $ipIf = Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            $gw = Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1
            $dns = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
            $rows.Add([pscustomobject]@{
                adapter    = $a.Name
                uplink     = ($a.ifIndex -eq $uplinkIdx)
                mac        = ($a.MacAddress -replace '-', ':')
                addressing = if ($ipIf -and $ipIf.Dhcp -eq 'Enabled') { 'DHCP' } elseif ($ipIf) { 'Static' } else { $null }
                ipAddress  = if ($ip) { $ip.IPAddress } else { $null }
                subnetMask = if ($ip) { ConvertTo-SubnetMask $ip.PrefixLength } else { $null }
                gateway    = if ($gw) { $gw.NextHop } else { $null }
                dns1       = if ($dns.Count -ge 1) { $dns[0] } else { $null }
                dns2       = if ($dns.Count -ge 2) { $dns[1] } else { $null }
            })
        }
    }
    catch {
        Write-Log "IP configuration unavailable: $($_.Exception.Message)"
    }
    # .ToArray(), never @($rows): on 5.1 @() over a Generic List throws
    # "Argument types do not match" (pulse CLAUDE.md rule 7). The leading
    # comma keeps a one-row result an array instead of unrolling it.
    return ,$rows.ToArray()
}

function Show-IpConfig($Rows) {
    Write-Section "This computer's IP configuration"
    if (-not $Rows -or $Rows.Count -eq 0) { Write-Host '  Not found: no adapter has a default gateway, or the IP configuration could not be read.' -ForegroundColor Yellow; return }
    foreach ($r in $Rows) {
        Write-Host "  $($r.adapter)  (internet connection)" -ForegroundColor White
        Write-Host ("    MAC address  {0}" -f $r.mac)
        Write-Host ("    Addressing   {0}" -f $r.addressing)
        Write-Host ("    IP address   {0}" -f $r.ipAddress)
        Write-Host ("    Subnet mask  {0}" -f $r.subnetMask)
        Write-Host ("    Gateway      {0}" -f $r.gateway)
        Write-Host ("    DNS 1        {0}" -f $r.dns1)
        Write-Host ("    DNS 2        {0}" -f $(if ($r.dns2) { $r.dns2 } else { 'None' }))
    }
    Write-Host ''
    Write-Wrapped 'Note: verify this IP configuration matches the Pixellot''s network before continuing with the test.' '' 'Yellow'
}

# ---------------------------------------------------------------- questions

function Read-Answer([string]$Question, [switch]$NoUnsure) {
    # Y, N or ? (not sure). "Not sure" is a real answer for someone who
    # isn't the network admin; it is recorded and flagged, never forced.
    $choices = if ($NoUnsure) { 'Y/N' } else { 'Y/N/?' }
    while ($true) {
        $a = ([string](Read-Host "$Question ($choices)")).Trim().ToUpper()
        $ans = switch -Regex ($a) {
            '^(Y|YES)$'                         { 'yes' }
            '^(N|NO)$'                          { 'no' }
            '^(\?|NOT SURE|UNSURE|DK|IDK|U)$'   { if (-not $NoUnsure) { 'unsure' } }
        }
        if ($ans) { Write-Log "Q: $($Question.Trim()) -> $ans"; return $ans }
        Write-Host $(if ($NoUnsure) { '  Please answer Y or N.' } else { '  Please answer Y, N, or ? if you are not sure.' }) -ForegroundColor Yellow
    }
}

function Test-OnPixellot {
    # The Pixellot's own software lives here. Running on the unit itself means
    # the results are the Pixellot's own network, so the VLAN question is moot.
    return (Test-Path -LiteralPath 'C:\Pixellot\Bin\CoordinatorCore.dll')
}

function Invoke-PreTestQuestions($Endpoints, [bool]$OnPixellot, [string]$PresetVenue, [string]$PresetId, [bool]$NoSpeedTest) {
    # Answers go in the report so support can tell a real result from one run
    # on the wrong network. Returns $null if the person chose to stop.
    $ans = [ordered]@{ venue = $null; pixellotId = $null; sameVlan = $null; dedicatedVlan = $null; rulesConfigured = $null; speedTest = $null }

    # A blank line before each question keeps every question and its
    # follow-up hint together as one block.
    Write-Section 'A few questions'
    Write-Host 'Answer Y (yes), N (no), or ? if you are not sure.'
    # Venue and Pixellot ID are not asked; they come from -Venue and
    # -PixellotId, and on a Pixellot the ID defaults to the computer name.
    $ans.venue = $PresetVenue
    $ans.pixellotId = if ($PresetId) { $PresetId } elseif ($OnPixellot) { [Environment]::MachineName } else { '' }

    Write-Host ''
    if ($OnPixellot) {
        $ans.sameVlan = 'self'
        Write-Host 'This is running on the Pixellot itself, so the results are its own network.' -ForegroundColor Green
        Write-Log 'Running on a Pixellot: same-VLAN question skipped'
    }
    else {
        $ans.sameVlan = Read-Answer 'Is this computer plugged into the same VLAN as the Pixellot?'
        if ($ans.sameVlan -eq 'unsure') {
            Write-Wrapped 'Ask your network team which VLAN the Pixellot''s switch port is on. The test will still run, and the report will note that this is unconfirmed.' '  ' 'Yellow'
        }
        elseif ($ans.sameVlan -eq 'no') {
            Write-Wrapped 'Results only apply to the network this computer is on. For a real answer, plug it into the Pixellot''s VLAN (or a switch port with the same settings).' '  ' 'Yellow'
            if ((Read-Answer '  Run the test anyway?' -NoUnsure) -eq 'no') { return $null }
        }
    }

    Write-Host ''
    $ans.dedicatedVlan = Read-Answer 'Is the Pixellot on its own VLAN (separate from staff and students)?'
    if ($ans.dedicatedVlan -ne 'yes') {
        Write-Wrapped 'Recommended: its own VLAN keeps streaming traffic away from the content filters and bandwidth limits used for staff and student devices.' '  ' 'Yellow'
    }

    Write-Host ''
    Write-Wrapped 'The firewall rules the Pixellot needs are in the NFHS Network article below, and the report will list them too.'
    if ($Endpoints.docUrl) {
        Write-Host "  $($Endpoints.docUrl)"
        Write-Host ''
        Write-Wrapped 'Saying yes opens the NFHS Network knowledge base article in your web browser.'
        if ((Read-Answer 'Would you like to review the firewall article now?' -NoUnsure) -eq 'yes') {
            # Only an https link is handed to Start-Process, which would
            # otherwise run whatever program or file the string names.
            $opened = $false
            if ($Endpoints.docUrl -match '^https://') {
                try { Start-Process $Endpoints.docUrl; $opened = $true }
                catch { Write-Log "Could not open docUrl in the browser: $($_.Exception.Message)" }
            }
            if ($opened) {
                Write-Wrapped 'Opened in your browser. Come back to this window when you are ready to continue.' '  ' 'Green'
            }
            else {
                Write-Wrapped 'Could not open the browser. Copy the link above into a browser to read the article.' '  ' 'Yellow'
            }
        }
    }
    Write-Host ''
    $ans.rulesConfigured = Read-Answer 'Has your network team set up these firewall rules for the Pixellot?'
    if ($ans.rulesConfigured -ne 'yes') {
        Write-Wrapped 'No problem: the test will show what is blocked right now, which works as a to-do list.' '  '
    }

    # Opt-in: the speed test fills the connection for up to 20 s, which
    # matters on a metered link or a busy network.
    if ($NoSpeedTest) {
        $ans.speedTest = 'no'
    }
    elseif ($Endpoints.speedTest) {
        $min = $Endpoints.speedTest.minMbps
        Write-Host ''
        Write-Wrapped ("The Pixellot needs at least $min Mbps download and $min Mbps upload, steadily, to stream. The speed test measures this in up to 20 seconds using speed.cloudflare.com. " +
            'While it runs it uses as much of the connection as it can, and it transfers up to about 60 MB. Skip it if the connection is metered (cellular) or busy with something that can''t be slowed down.')
        Write-Host ''
        $ans.speedTest = Read-Answer 'Run the speed test?' -NoUnsure
        if ($ans.speedTest -eq 'no') {
            Write-Wrapped "Skipped. Confirm another way that the Pixellot's connection has at least $min Mbps each way. The report will note that speed was not measured." '  ' 'Yellow'
        }
    }
    return [pscustomobject]$ans
}

# ---------------------------------------------------------------- report

function ConvertTo-HtmlSafe([string]$s) {
    if ($null -eq $s) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($s)
}

# ---------------------------------------------------------------- verdict

function Format-Count([int]$N, [string]$One, [string]$Many) {
    if ($N -eq 1) { return "1 $One" }
    return "$N $Many"
}

function Get-SeverityRank([string]$Severity) {
    switch ($Severity) { 'critical' { 0 } 'high' { 1 } 'medium' { 2 } default { 3 } }
}

function Get-StreamPathSummary($Mine) {
    # Streaming has three paths tried in order (primary, backup, last
    # resort), so what a block means depends on which path still gets
    # through. Says which are blocked and which the stream would use;
    # returns nothing when no blocked check is part of the chain.
    $paths = @($Mine | Where-Object { $_.path })
    $blocked = @($paths | Where-Object { $_.status -eq 'fail' })
    if ($blocked.Count -eq 0) { return $null }
    $label = { param($r) "$(($r.target -split ' -> ')[0]) ($($r.path))" }
    $names = @($blocked | ForEach-Object { & $label $_ })
    $list = if ($names.Count -le 2) { $names -join ' and ' } else { ($names[0..($names.Count - 2)] -join ', ') + ' and ' + $names[-1] }
    $verb = if ($names.Count -eq 1) { 'is' } else { 'are' }
    $use = $paths | Where-Object { $_.status -eq 'pass' } | Select-Object -First 1
    $then = if (-not $use) {
        'so the broadcast cannot go on air.'
    }
    elseif ($use -eq $paths[0]) {
        "so the stream has less to fall back on if the $($use.path) path drops."
    }
    elseif ($use -eq $paths[-1]) {
        "so streams would fall back to $(& $label $use) and start about 4 minutes late."
    }
    else {
        "so streams would fall back to $(& $label $use)."
    }
    return "$list $verb blocked, $then Open every streaming path before go-live."
}

function Get-Verdict($Results, $Services) {
    # Strict by design: any critical or high failure is Not ready, including
    # UDP 2088 alone even though the stream would fall back to UDP 443. New
    # sites should start with every port open. The per-service lines carry
    # the nuance; the verdict does not soften it.
    $blocking = @($Results | Where-Object { $_.status -eq 'fail' -and (Get-SeverityRank $_.severity) -le 1 })
    $other    = @($Results | Where-Object { ($_.status -eq 'fail' -and (Get-SeverityRank $_.severity) -ge 2) -or $_.status -eq 'warn' })

    $svcRows = New-Object System.Collections.Generic.List[object]
    foreach ($s in $Services) {
        $mine = @($Results | Where-Object { $_.service -eq $s.id })
        if ($mine.Count -eq 0) { continue }
        $bad   = @($mine | Where-Object { $_.status -eq 'fail' -and (Get-SeverityRank $_.severity) -le 1 })
        $check = @($mine | Where-Object { ($_.status -eq 'fail' -and (Get-SeverityRank $_.severity) -ge 2) -or $_.status -eq 'warn' })
        if ($bad.Count -gt 0) {
            # The first failure's own consequence beats the generic service
            # line: "falls back to UDP 443" says more than "cannot stream".
            # Streaming paths are judged together, since the outcome depends
            # on which path still gets through.
            $why = ($bad | Where-Object { $_.consequence } | Select-Object -First 1).consequence
            if (-not $why) { $why = $s.blocked }
            $status = 'fail'
            $summary = Get-StreamPathSummary $mine
            if (-not $summary) { $summary = "$($bad.Count) of $(Format-Count $mine.Count 'check' 'checks') failed. $why" }
        }
        elseif ($check.Count -gt 0) {
            $status = 'check'
            $summary = "Check: " + (($check | ForEach-Object { $_.target }) -join ', ') + '.'
        }
        else {
            $status = 'ok'
            $summary = if ($mine.Count -eq 1) { 'Check passed.' } else { "All $($mine.Count) checks passed." }
        }
        $svcRows.Add([pscustomobject]@{ id = $s.id; name = $s.name; status = $status; summary = $summary })
    }

    if ($blocking.Count -gt 0) {
        $state = 'not-ready'
        $headline = "Not ready: $(Format-Count $blocking.Count 'problem' 'problems') to fix"
        $sub = 'The Pixellot will not work fully on this network until the changes below are made.'
    }
    elseif ($other.Count -gt 0) {
        $state = 'issues'
        $headline = "Ready, with $(Format-Count $other.Count 'item' 'items') to check"
        $sub = 'Nothing required is blocked, but review the items below.'
    }
    else {
        $state = 'ready'
        $headline = 'Ready to stream: every check passed'
        $sub = 'This network allows everything this tool tests.'
    }
    return [pscustomobject]@{
        state    = $state
        headline = $headline
        detail   = $sub
        blocking = $blocking.Count
        toCheck  = $other.Count
        services = $svcRows.ToArray()
    }
}

function Get-ChangeGroups($Results, $Services) {
    # One entry per change to make, not per failed probe: three Singular hosts
    # failing inspection is one firewall change. Most severe first, then in
    # service order, so the first entry is where IT should start. Shared by
    # the HTML report and the console so both list the same changes.
    $order = @{}; $name = @{}; $i = 0
    foreach ($s in $Services) { $order[$s.id] = $i; $name[$s.id] = $s.name; $i++ }
    $failed = @($Results | Where-Object { $_.fix -and $_.status -ne 'pass' })
    if ($failed.Count -eq 0) { return @() }
    $groups = $failed | Group-Object -Property fix | ForEach-Object {
        $items = @($_.Group)
        # A warning (could not measure) is never Critical, whatever the
        # severity of the requirement it was testing: it sorts last as Check.
        $rank = ($items | ForEach-Object { if ($_.status -eq 'warn') { 3 } else { Get-SeverityRank $_.severity } } | Measure-Object -Minimum).Minimum
        $svc  = ($items | ForEach-Object { $order[$_.service] } | Measure-Object -Minimum).Minimum
        [pscustomobject]@{
            fix         = $_.Name
            items       = $items
            rank        = $rank
            svc         = $svc
            severity    = @('Critical', 'High', 'Medium', 'Check')[[int]$rank]
            affects     = ($items | ForEach-Object { $name[$_.service] } | Select-Object -Unique) -join ', '
            consequence = ($items | Where-Object { $_.consequence } | Select-Object -First 1).consequence
        }
    }
    return @($groups | Sort-Object rank, svc)
}

function Get-RuleSheet($Rules, $Results) {
    # One row per firewall rule, with this run's result beside it, so IT can
    # copy the rules into the firewall and see which ones are already in
    # effect. A rule's priority is that of its most severe check; a rule no
    # check tests is shown as not tested rather than passed.
    foreach ($rule in $Rules) {
        $mine = @($Results | Where-Object { $_.ruleId -eq $rule.id })
        $failed = @($mine | Where-Object { $_.status -eq 'fail' })
        $warned = @($mine | Where-Object { $_.status -eq 'warn' })
        $tested = @($mine | ForEach-Object { ($_.target -split ' -> ')[-1] } | Select-Object -Unique)
        if ($rule.optional) { $priority = 'Optional' }
        elseif ($mine.Count -gt 0) {
            $rank = ($mine | ForEach-Object { Get-SeverityRank $_.severity } | Measure-Object -Minimum).Minimum
            $priority = @('Critical', 'High', 'Medium', '')[[int]$rank]
        }
        else { $priority = '' }
        $evidence = { param($set) ($set | ForEach-Object { "$($_.category) $($_.target -replace ' -> ', ' to '): $(Get-ShortNote $_)" }) -join '; ' }
        if ($mine.Count -eq 0) {
            $status = 'untested'
            $summary = 'No check in this tool covers this rule.'
        }
        elseif ($failed.Count -gt 0) {
            $status = 'fail'
            $summary = if ($mine.Count -eq 1) { "Failed: $(& $evidence $failed)." }
                else { "$($failed.Count) of $($mine.Count) checks failed: $(& $evidence $failed)." }
        }
        elseif ($warned.Count -gt 0) {
            $status = 'warn'
            $summary = "Could not confirm: $(& $evidence $warned)."
        }
        else {
            $status = 'pass'
            $summary = if ($mine.Count -eq 1) { 'Check passed.' } else { "All $($mine.Count) checks passed." }
        }
        [pscustomobject]@{
            id          = $rule.id
            priority    = $priority
            protocol    = $rule.protocol
            port        = [string]$rule.port
            destination = $rule.destination
            inspection  = [bool]$rule.inspection
            purpose     = $rule.purpose
            note        = $rule.note
            optional    = $rule.optional
            status      = $status
            summary     = $summary
            tested      = $tested
        }
    }
}

function Write-RuleCsv($Rows, [string]$Path) {
    # The rule sheet as a spreadsheet, to import or forward to whoever runs
    # the firewall. ASCII text, so Excel opens it the same with or without
    # a BOM.
    $word = @{ pass = 'PASS'; fail = 'FAIL'; warn = 'WARN'; untested = 'Not tested' }
    $csv = $Rows | ForEach-Object {
        [pscustomobject]@{
            'Priority'                   = $_.priority
            'Direction'                  = 'Outbound'
            'Source'                     = 'Pixellot (its IP address or VLAN)'
            'Protocol'                   = $_.protocol
            'Port'                       = $_.port
            'Destination'                = $_.destination
            'Exempt from SSL inspection' = $(if ($_.inspection) { 'Yes' } else { '' })
            'Needed for'                 = $_.purpose
            'Notes'                      = $_.note
            'Result this run'            = $word[$_.status]
            'Details'                    = $_.summary
            'Tested against'             = ($_.tested -join ', ')
        }
    } | ConvertTo-Csv -NoTypeInformation
    [System.IO.File]::WriteAllText($Path, (($csv -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
}

function Write-HtmlReport($Report, [string]$Path) {
    # Reading order follows the IT admin's task: the verdict, what to change,
    # where the test ran (so the result can be trusted), what this tool can't
    # see, then every check for reference. Passing detail is collapsed by
    # service; printing expands it.
    $v = $Report.verdict
    $svcName = @{}
    foreach ($s in $v.services) { $svcName[$s.id] = $s.name }
    $sevLabel = @{ critical = 'Critical'; high = 'High'; medium = 'Medium' }
    $tagWord = @{ pass = 'PASS'; fail = 'FAIL'; warn = 'WARN'; ok = 'OK'; check = 'WARN' }
    $c = $Report.context
    $q = $Report.answers
    $h = { param($t) ConvertTo-HtmlSafe ([string]$t) }

    # ---- verdict and services
    $caveats = @()
    if ($q.sameVlan -eq 'no') { $caveats += 'This test was not run from the Pixellot''s VLAN, so these results may not match what the Pixellot sees.' }
    elseif ($q.sameVlan -eq 'unsure') { $caveats += 'It is not confirmed that this computer was on the Pixellot''s VLAN, so these results may not match what the Pixellot sees.' }
    if ($c.connection -eq 'Wi-Fi') { $caveats += 'This computer was on Wi-Fi. Pixellots are wired, so a wired run on the Pixellot''s switch port is more reliable.' }
    $caveatHtml = ($caveats | ForEach-Object { "<p class='caveat'><b>Note:</b> " + (& $h $_) + '</p>' }) -join ''
    $svcRows = foreach ($s in $v.services) {
        $st = if ($s.status -eq 'ok') { 'pass' } elseif ($s.status -eq 'fail') { 'fail' } else { 'warn' }
        "<tr><th scope='row'>$(& $h $s.name)</th><td><span class='tag tag-$st'>$($tagWord[$s.status])</span></td><td>$(& $h $s.summary)</td></tr>"
    }
    $verdictHtml = "<section class='verdict $($v.state)' aria-labelledby='verdict-h'>" +
        "<h2 id='verdict-h' class='headline'>$(& $h $v.headline)</h2><p class='verdict-detail'>$(& $h $v.detail)</p>$caveatHtml" +
        "<table class='services stack'><caption>What works on this network</caption>" +
        "<thead><tr><th scope='col'>Service</th><th scope='col'>Status</th><th scope='col'>Details</th></tr></thead><tbody>" +
        ($svcRows -join '') + '</tbody></table></section>'

    # ---- changes needed (one row per change, most severe first)
    $failedResults = @($Report.results | Where-Object { $_.fix -and $_.status -ne 'pass' })
    $groups = Get-ChangeGroups $Report.results $v.services
    $ruleRows = @(); $n = 0
    foreach ($g in $groups) {
        $n++
        # Bold only the first sentence: that is the rule to add. The rest is
        # the reason, which reads better at normal weight.
        $m = [regex]::Match($g.fix, '^(.+?\.)(\s+.*)?$')
        $change = if ($m.Success) { '<b>' + (& $h $m.Groups[1].Value) + '</b>' + (& $h $m.Groups[2].Value) } else { '<b>' + (& $h $g.fix) + '</b>' }
        if ($g.consequence) { $change += "<span class='sub'>" + (& $h $g.consequence) + '</span>' }
        $evidence = ($g.items | ForEach-Object {
            "<li><span class='check'>" + (& $h ("$($_.category) " + ($_.target -replace ' -> ', ' to '))) + "</span> <span class='when'>at $($_.time)</span><br>" +
                (& $h $_.detail) + '</li>'
        }) -join ''
        $sevClass = if ($g.severity) { $g.severity.ToLower() } else { 'none' }
        $ruleRows += "<tr><td data-label='#' class='num'>$n</td><td data-label='Priority'><span class='sev sev-$sevClass'>$($g.severity)</span></td>" +
            "<td data-label='Affects'>$(& $h $g.affects)</td><td data-label='$(if ($v.state -eq 'issues') { 'What to do' } else { 'Change to make' })'>$change</td>" +
            "<td data-label='What failed'><ul class='evidence'>$evidence</ul></td></tr>"
    }
    $changesHtml = ''
    if ($ruleRows.Count -gt 0) {
        # With nothing blocked, the rows are follow-ups, not firewall changes.
        $changesTitle = if ($v.state -eq 'issues') { 'Items to check' } else { 'Changes needed' }
        $changesLede = if ($v.state -eq 'issues') { 'Nothing required is blocked. These checks could not finish; follow up on each row.' }
            else { 'Each row is one firewall or filter change. Start at row 1. The evidence column has the address tried and the time, to match against your firewall logs.' }
        $changesHtml = "<section aria-labelledby='changes-h'><h2 id='changes-h'>$changesTitle</h2>" +
            "<p class='lede'>$changesLede</p>" +
            "<table class='changes stack'><thead><tr><th scope='col'>#</th><th scope='col'>Priority</th><th scope='col'>Affects</th><th scope='col'>$(if ($v.state -eq 'issues') { 'What to do' } else { 'Change to make' })</th><th scope='col'>What failed</th></tr></thead><tbody>" +
            ($ruleRows -join "`n") + '</tbody></table>'
        if (@($failedResults | Where-Object { $_.category -eq 'TLS' }).Count -gt 0 -and $Report.patternNote) {
            $changesHtml += "<p class='note'><b>About SSL inspection exemptions:</b> " + (& $h $Report.patternNote) + '</p>'
        }
        $changesHtml += '</section>'
    }

    # ---- where the test ran
    $fmt = { param($x) switch ($x) { 'yes' { 'Yes' } 'no' { 'No' } 'unsure' { 'Not sure' } 'self' { 'Yes (run on the Pixellot itself)' } default { 'Not asked' } } }
    $ip = @($Report.ipConfig) | Select-Object -First 1
    $net = [ordered]@{
        'Computer'    = "$($c.computer)"
        'Connection'  = $(if ($c.connection) { "$($c.connection)" + $(if ($ip) { " ($($ip.adapter))" } else { '' }) } else { 'Unknown' })
        'MAC address' = $(if ($ip) { $ip.mac } else { '' })
        'Addressing'  = $(if ($ip) { $ip.addressing } else { '' })
        'IP address'  = $(if ($ip) { $ip.ipAddress } else { $c.localIp })
        'Subnet mask' = $(if ($ip) { $ip.subnetMask } else { '' })
        'Gateway'     = $(if ($ip) { $ip.gateway } else { $c.gateway })
        'DNS 1'       = $(if ($ip) { $ip.dns1 } else { $c.dns })
        'DNS 2'       = $(if ($ip -and $ip.dns2) { $ip.dns2 } else { 'None' })
        'Public IP'   = $(if ($c.publicIp) { $c.publicIp } else { 'Could not be determined' })
    }
    $netHtml = ($net.Keys | ForEach-Object { "<dt>$_</dt><dd>" + $(if ($net[$_]) { & $h $net[$_] } else { '&mdash;' }) + '</dd>' }) -join ''
    # Venue and Pixellot ID are shown only when given (-Venue, -PixellotId,
    # or the computer name on a Pixellot).
    $ansHtml = $(if ($q.venue) { "<dt>Venue</dt><dd>$(& $h $q.venue)</dd>" } else { '' }) +
        $(if ($q.pixellotId) { "<dt>Pixellot ID</dt><dd>$(& $h $q.pixellotId)</dd>" } else { '' }) +
        "<dt>Same VLAN as the Pixellot</dt><dd>$(& $fmt $q.sameVlan)</dd>" +
        "<dt>Pixellot on its own VLAN</dt><dd>$(& $fmt $q.dedicatedVlan)</dd>" +
        "<dt>Firewall rules set up</dt><dd>$(& $fmt $q.rulesConfigured)</dd>" +
        "<dt>Speed test</dt><dd>$(if ($q.speedTest -eq 'no') { 'Skipped' } else { 'Run' })</dd>"
    if ($q.rulesConfigured -eq 'yes' -and $v.blocking -gt 0) {
        $ansHtml += "<dd class='mismatch' style='grid-column:1/-1'>Answered Yes, but $(Format-Count $v.blocking 'required check' 'required checks') failed. Some rules are missing or not in effect.</dd>"
    }
    $contextHtml = "<section class='context' aria-labelledby='context-h'><h2 id='context-h'>Where this test ran</h2>" +
        "<div class='context-grid'><div><h3>Network connection</h3><dl>$netHtml</dl></div>" +
        "<div><h3>Answers given</h3><dl>$ansHtml</dl></div></div></section>"

    # ---- the rules themselves, from the NFHS article, so the report is
    # self-contained when it is emailed or printed
    # One row per rule, with this run's result, so the sheet doubles as a
    # checklist: rows that passed are already in effect.
    $reqHtml = ''
    if ($Report.rules) {
        $ruleWord = @{ pass = 'PASS'; fail = 'FAIL'; warn = 'WARN' }
        $ruleRows = foreach ($r in $Report.rules) {
            $pri = if ($r.priority) { "<span class='sev sev-$($r.priority.ToLower())'>$($r.priority)</span>" } else { '' }
            if ($r.optional) { $pri += "<span class='sub'>$(& $h $r.optional)</span>" }
            $dest = (($r.destination -split ',\s*') | ForEach-Object { '<code>' + (& $h $_) + '</code>' }) -join '<br>'
            if ($r.note) { $dest += "<span class='sub'>$(& $h $r.note)</span>" }
            $ssl = if ($r.inspection) { 'Exempt' } else { "<span class='muted'>&mdash;</span>" }
            $res = if ($r.status -eq 'untested') { "<span class='muted'>Not tested</span>" }
                else { "<span class='tag tag-$($r.status)'>$($ruleWord[$r.status])</span>" }
            $res += "<span class='sub'>$(& $h $r.summary)</span>"
            "<tr class='rule-$($r.status)'><td data-label='Priority'>$pri</td><td data-label='Port' class='port'>$($r.protocol) $(& $h $r.port)</td>" +
                "<td data-label='Destination'>$dest</td><td data-label='Needed for'>$(& $h $r.purpose)</td>" +
                "<td data-label='SSL inspection'>$ssl</td><td data-label='This run' class='res'>$res</td></tr>"
        }
        $csvLink = if ($Report.rulesCsv) { " The same sheet is saved as <a href='$(& $h $Report.rulesCsv)'>$(& $h $Report.rulesCsv)</a>, to import or forward to whoever manages the firewall." } else { '' }
        $docLink = if ($Report.docUrl) { "<a href='$(& $h $Report.docUrl)'>NFHS Network firewall article</a>" } else { 'NFHS Network firewall article' }
        $reqHtml = "<section aria-labelledby='req-h'><h2 id='req-h'>Firewall rule sheet</h2>" +
            "<p class='lede'>Every rule the Pixellot needs, from the $docLink, with this run's result. Each rule is outbound from the Pixellot's IP address (or its VLAN); no inbound rules are needed. Don't rate-limit the Pixellot or put it on an internet sleep schedule.$csvLink</p>" +
            "<table class='rules stack'><thead><tr><th scope='col'>Priority</th><th scope='col'>Port</th><th scope='col'>Destination</th><th scope='col'>Needed for</th><th scope='col'>SSL inspection</th><th scope='col'>This run</th></tr></thead><tbody>" +
            ($ruleRows -join "`n") + '</tbody></table></section>'
    }

    # ---- current addresses behind each domain, for IP-based firewalls
    $addrHtml = ''
    if ($Report.addresses) {
        $addrRows = foreach ($d in $Report.addresses) {
            $dom = "<td data-label='Domain rule' rowspan='1'><code>$(& $h $d.domain)</code></td>"
            if (-not $d.hosts) {
                "<tr>$dom<td data-label='Host' colspan='2' class='muted'>No fixed host names to look up. Use the domain rule.</td></tr>"
                continue
            }
            $dom = "<td data-label='Domain rule' rowspan='$(@($d.hosts).Count)'><code>$(& $h $d.domain)</code></td>"
            foreach ($a in $d.hosts) {
                $ips =if ($a.error) { "<span class='muted'>Not resolved: $(& $h $a.error)</span>" }
                       else { ($a.ipv4 | ForEach-Object { '<code>' + (& $h $_) + '</code>' }) -join '<br>' }
                $alias = if ($a.aliases) { "<span class='sub'>Alias of $(& $h ($a.aliases -join ' to ')). Addresses may change often.</span>" } else { '' }
                "<tr>$dom<td data-label='Host'><code>$(& $h $a.host)</code>$alias</td><td data-label='IPv4 addresses'>$ips</td></tr>"
                $dom = ''
            }
        }
        $allIps = @($Report.addresses | ForEach-Object { $_.hosts } | ForEach-Object { $_.ipv4 } | Where-Object { $_ } | Sort-Object { [version]$_ } -Unique)
        $ai = $Report.addressInfo
        $via = if ($ai.resolver) { " through DNS server $(& $h $ai.resolver)" } else { '' }
        $addrHtml = "<section aria-labelledby='addr-h'><h2 id='addr-h'>Current IP addresses</h2>" +
            "<p class='lede'>For firewalls that need IP addresses instead of domain names. Looked up from this computer at $($ai.time)$via. Cloud and CDN addresses change and can differ by location, so domain rules are still the better choice; if you use these, check them again before each season. Streaming servers (<code>*.pixellot.stream</code>) are assigned per event and can't be listed.</p>" +
            "<table class='addr stack'><thead><tr><th scope='col'>Domain rule</th><th scope='col'>Host</th><th scope='col'>IPv4 addresses</th></tr></thead><tbody>" +
            ($addrRows -join "`n") + '</tbody></table>'
        if ($allIps) {
            $addrHtml += "<details class='iplist'><summary>All $($allIps.Count) addresses as one list, to copy</summary><pre>$(($allIps | ForEach-Object { & $h $_ }) -join "`n")</pre></details>"
        }
        $addrHtml += '</section>'
    }

    # ---- every check, grouped by service; services with problems open
    $svcBlocks = foreach ($s in $v.services) {
        $mine = @($Report.results | Where-Object { $_.service -eq $s.id })
        $rows = foreach ($r in $mine) {
            $res = "<span class='tag tag-$($r.status)'>$($tagWord[$r.status])</span>"
            # Severity only on failures: a warning (could not measure) is not Critical.
            if ($r.status -eq 'fail' -and $r.severity) { $res += " <span class='sev sev-$($r.severity)'>$($sevLabel[$r.severity])</span>" }
            $target = & $h ($r.target -replace ' -> ', ' to ')
            "<tr><td data-label='Result' class='res'>$res</td><td data-label='Check'><b>$($r.category)</b> $target<span class='sub'>$(& $h $r.purpose)</span></td>" +
                "<td data-label='Detail'>$(& $h $r.detail)<span class='sub'>at $($r.time)</span></td></tr>"
        }
        $st = if ($s.status -eq 'ok') { 'pass' } elseif ($s.status -eq 'fail') { 'fail' } else { 'warn' }
        $open = if ($s.status -ne 'ok') { ' open' } else { '' }
        "<details$open><summary><span class='tag tag-$st'>$($tagWord[$s.status])</span> <b>$(& $h $s.name)</b> <span class='sum'>$(& $h ($s.summary -replace '\. .*$', '.'))</span></summary>" +
            "<table class='checks stack'><thead><tr><th scope='col'>Result</th><th scope='col'>Check</th><th scope='col'>Detail</th></tr></thead><tbody>" +
            ($rows -join "`n") + '</tbody></table></details>'
    }
    $allHtml = "<section aria-labelledby='all-h'><h2 id='all-h'>All checks</h2>" +
        "<p class='lede'>$($Report.summary.total) checks, grouped by what they affect. Groups with problems are open; select a group to see its checks.</p>" +
        ($svcBlocks -join "`n") + '</section>'

    # ---- page
    $stateWord = @{ 'not-ready' = 'NOT READY'; 'issues' = 'READY WITH ITEMS TO CHECK'; 'ready' = 'READY' }[$v.state]
    # @() so that with neither given this is an empty array, not $null.
    $who = @(@($Report.venue, $q.pixellotId) | Where-Object { $_ })
    $title = (@('VPU Network Check') + $who + @($stateWord, $Report.timestamp.Substring(0, 10))) -join ' - '
    $metaWho = @(@($Report.venue, $(if ($q.pixellotId) { 'Pixellot ' + $q.pixellotId })) | Where-Object { $_ } | ForEach-Object { & $h $_ })
    $meta = ($metaWho + @((& $h $Report.timestamp), ('run from ' + (& $h $c.computer)))) -join ' &middot; '
    $files = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>$(& $h $title)</title>
<style>
:root{--ink:#1b1d21;--muted:#5a5f68;--line:#d9dce1;--line-soft:#eceef1;--paper:#fff;--tint:#f6f7f9;
--pass:#0b6b2e;--fail:#a1001f;--warn:#8a4b00;--fail-bg:#fbeff1;--fail-line:#e7bcc4;--warn-bg:#fcf5ea;--warn-line:#ebd3a8;--pass-bg:#edf6f0;--pass-line:#b2d6bd;
--s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;--s7:48px}
*{box-sizing:border-box}
html{background:var(--paper)}
body{margin:0;color:var(--ink);background:var(--paper);font:15px/1.5 "Segoe UI",system-ui,-apple-system,Arial,sans-serif;font-variant-numeric:tabular-nums}
::selection{background:#cfe3ff}
main{max-width:1040px;margin:0 auto;padding:var(--s6) var(--s4) var(--s7)}
h1{font-size:28px;line-height:1.3;margin:0 0 var(--s1)}
h2{font-size:20px;line-height:1.35;margin:var(--s7) 0 var(--s2)}
h3{font-size:15px;margin:0 0 var(--s2)}
a{color:#0b5cad;text-underline-offset:2px}
.meta,.lede,.sub,.when{color:var(--muted)}
.meta{font-size:14px;margin:0}
.lede{margin:0 0 var(--s3);max-width:72ch}
.sub{display:block;font-size:13px;margin-top:2px}
.when{font-size:13px;white-space:nowrap}
table{border-collapse:collapse;width:100%;font-size:14px;line-height:1.45}
caption{text-align:left;font-weight:600;padding:0 0 var(--s2)}
th,td{text-align:left;vertical-align:top;padding:var(--s2) var(--s3);border-bottom:1px solid var(--line-soft)}
thead th{font-size:13px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line)}
.tag{display:inline-block;min-width:44px;text-align:center;font-size:12px;font-weight:700;letter-spacing:.02em;padding:1px var(--s2);border-radius:3px;border:1px solid}
.tag-pass{color:var(--pass);background:var(--pass-bg);border-color:var(--pass-line)}
.tag-fail{color:var(--fail);background:var(--fail-bg);border-color:var(--fail-line)}
.tag-warn{color:var(--warn);background:var(--warn-bg);border-color:var(--warn-line)}
.sev{font-size:13px;font-weight:700;white-space:nowrap}
.sev-critical{color:var(--fail)}.sev-high{color:var(--warn)}.sev-medium,.sev-check{color:var(--muted)}
.verdict{margin:var(--s5) 0 0;padding:var(--s5);border:1px solid var(--line);border-radius:6px}
.verdict.not-ready{background:var(--fail-bg);border-color:var(--fail-line)}
.verdict.issues{background:var(--warn-bg);border-color:var(--warn-line)}
.verdict.ready{background:var(--pass-bg);border-color:var(--pass-line)}
.verdict .headline{font-size:24px;line-height:1.3;margin:0 0 var(--s1)}
.verdict.not-ready .headline{color:var(--fail)}.verdict.issues .headline{color:var(--warn)}.verdict.ready .headline{color:var(--pass)}
.verdict-detail{margin:0 0 var(--s4)}
.caveat{margin:0 0 var(--s4);padding:var(--s2) var(--s3);background:var(--paper);border:1px solid var(--warn-line);border-radius:4px;color:var(--warn)}
table.services{background:var(--paper);border:1px solid var(--line);border-radius:4px}
table.services caption{padding-top:0}
table.services th[scope=row]{white-space:nowrap;font-weight:600}
table.changes td.num{font-weight:700;width:2.5em}
table.changes td:nth-child(4){min-width:280px}
ul.evidence{margin:0;padding-left:var(--s4)}
ul.evidence li{margin:0 0 var(--s2);overflow-wrap:anywhere}
.check{font-weight:600}
.note{margin:var(--s3) 0 0;padding:var(--s3) var(--s4);background:var(--tint);border-radius:4px;font-size:14px;max-width:80ch}
.context{margin-top:var(--s7);padding:var(--s5);background:var(--tint);border-radius:6px}
.context h2{margin-top:0}
.context-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:var(--s5)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:var(--s1) var(--s4);margin:0;font-size:14px}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
dd.mismatch{color:var(--fail);font-weight:600;margin-top:var(--s2)}
details{border:1px solid var(--line);border-radius:4px;margin:0 0 var(--s2)}
summary{cursor:pointer;padding:var(--s3) var(--s4);display:flex;gap:var(--s3);align-items:baseline;flex-wrap:wrap}
summary:focus-visible{outline:2px solid #0b5cad;outline-offset:2px}
summary .sum{color:var(--muted);font-size:14px}
details[open] summary{border-bottom:1px solid var(--line-soft)}
details table td.res{white-space:nowrap;width:1%}
footer{margin-top:var(--s7);padding-top:var(--s4);border-top:1px solid var(--line);font-size:13px;color:var(--muted)}
footer p{margin:0 0 var(--s1)}
.rules td.port{white-space:nowrap;font-weight:600}
table.rules td:nth-child(3){min-width:240px;overflow-wrap:anywhere}
table.rules td.res{min-width:180px}
table.rules tr.rule-fail td.port{color:var(--fail)}
code{font-family:Consolas,"Cascadia Mono",Menlo,monospace;font-size:13px}
.muted{color:var(--muted)}
table.addr td{overflow-wrap:anywhere}table.addr td[rowspan]{white-space:nowrap;border-right:1px solid var(--line-soft)}
table.addr tbody tr:has(td[rowspan]) td{border-top:1px solid var(--line)}
details.iplist{margin-top:var(--s3)}
details.iplist pre{margin:0;padding:var(--s3) var(--s4);font:13px/1.5 Consolas,"Cascadia Mono",Menlo,monospace;user-select:all}
dl,.note,.meta,summary,footer{line-height:1.5}
@media (max-width:680px){
  main{padding:var(--s5) var(--s4) var(--s6)}
  h1{font-size:24px}.verdict{padding:var(--s4)}.verdict .headline{font-size:21px}
  table.stack thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
  table.stack,table.stack tbody,table.stack tr,table.stack td,table.stack th[scope=row]{display:block;width:auto}
  table.stack tr{padding:var(--s3) 0;border-bottom:1px solid var(--line)}
  table.stack td,table.stack th[scope=row]{border:0;padding:var(--s1) var(--s3)}
  table.stack td[data-label]::before{content:attr(data-label);display:block;font-size:12px;font-weight:600;color:var(--muted)}
  table.changes td:nth-child(4){min-width:0}
  table.stack caption{display:block;padding:var(--s3) var(--s3) 0}
  table.changes td:nth-child(-n+3){display:inline-block;padding-right:0}
  table.changes td:nth-child(-n+3)::before{display:none}
  table.changes td:nth-child(2)::after,table.changes td:nth-child(1)::after{content:" \00b7";color:var(--muted)}
  dl{grid-template-columns:1fr}dt{margin-top:var(--s2)}
  table.rules td:nth-child(3),table.rules td.res{min-width:0}
  table.rules td:nth-child(-n+2){display:inline-block;padding-right:0}
  table.rules td:nth-child(-n+2)::before{display:none}
  table.rules td:nth-child(1)::after{content:" \00b7";color:var(--muted)}
  table.rules td:nth-child(1) .sub{display:inline;margin-left:var(--s1)}
}
@media print{
  body{font-size:12px}main{max-width:none;padding:0}
  .verdict,.tag,.context{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  h2{margin-top:var(--s5);break-after:avoid}tr,li,details summary{break-inside:avoid}
  summary{cursor:auto}a{color:inherit}a[href]::after{content:" (" attr(href) ")";font-size:11px;color:var(--muted)}
}
</style></head><body><main>
<header><h1>VPU Network Check</h1>
<p class="meta">$meta</p></header>
$verdictHtml
$changesHtml
$contextHtml
$reqHtml
$addrHtml
$allHtml
<footer>
<p>pulse-verify v$($Report.toolVersion). Run this from the network segment the Pixellot will use; a result from another VLAN or guest Wi-Fi does not apply to it.</p>
<p>Files from this run: $($files).html (this report), $($files)-rules.csv (the firewall rule sheet), $($files).json (results data), $($files).log in the logs folder (timings and errors).</p>
<p>If you believe the information in this report is incorrect, contact NFHS Network support at <a href='https://help.nfhsnetwork.com'>help.nfhsnetwork.com</a> and attach this report ($($files).html). A network specialist will review it and help you.</p>
</footer>
</main>
<script>window.addEventListener('beforeprint',function(){var d=document.querySelectorAll('details');for(var i=0;i<d.length;i++){d[i].open=true}});</script>
</body></html>
"@
    [System.IO.File]::WriteAllText($Path, $html, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------- main

# $PSScriptRoot is empty when the script is pasted into a console, run from an
# ISE selection, or launched some other way that isn't -File, which made the
# old param default (Join-Path $PSScriptRoot ...) throw "Cannot bind argument
# to parameter 'Path' because it is an empty string". Resolve it here instead.
$scriptDir = $PSScriptRoot
if (-not $scriptDir -and $MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
if (-not $EndpointsPath) { $EndpointsPath = Join-Path $scriptDir 'endpoints.json' }

# Settle the output folder and start the log BEFORE any test runs, so a bad
# path can't throw away a finished run at the very end.
# Reports and logs each get a folder next to the script so they don't pile
# up beside it. Either falls back to the script folder if it can't be
# created (e.g. the script is run from a read-only location).
if (-not $OutDir) {
    $OutDir = Join-Path $scriptDir 'reports'
    try { [void][System.IO.Directory]::CreateDirectory($OutDir) } catch { }
}
$requestedOutDir = $OutDir
$OutDir = Resolve-OutDir $OutDir $scriptDir
$logDir = Join-Path $scriptDir 'logs'
try { [void][System.IO.Directory]::CreateDirectory($logDir) } catch { }
$logDir = Resolve-OutDir $logDir $OutDir
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogPath = Join-Path $logDir "vpu-network-check-$stamp.log"
$jsonPath = Join-Path $OutDir "vpu-network-check-$stamp.json"
$htmlPath = Join-Path $OutDir "vpu-network-check-$stamp.html"
$csvPath  = Join-Path $OutDir "vpu-network-check-$stamp-rules.csv"

# Anything unexpected lands in the log with its stack before we exit.
trap {
    Write-Log ("UNHANDLED ERROR: " + $_.Exception.Message)
    Write-Log ("  at: " + $_.ScriptStackTrace)
    Write-Host "Unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    if ($script:LogPath) { Write-Host "Details were written to $($script:LogPath)" }
    exit 4
}

Write-Log "pulse-verify v$ToolVersion starting"
Write-Log ("PowerShell {0} ({1}) on {2}" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, [Environment]::OSVersion.VersionString)
Write-Log "Computer: $([Environment]::MachineName)  User: $([Environment]::UserName)"
Write-Log "Script folder: $scriptDir"
Write-Log "Endpoints: $EndpointsPath"
if ($requestedOutDir -ne $OutDir) { Write-Log "Output folder requested: [$requestedOutDir]  using: [$OutDir]" }
else { Write-Log "Output folder: $OutDir" }

if (-not (Test-Path -LiteralPath $EndpointsPath)) {
    Write-Log "endpoints.json not found at $EndpointsPath"
    Write-Host "Cannot find endpoints.json at $EndpointsPath" -ForegroundColor Red
    Write-Host 'Keep endpoints.json in the same folder as this script, or pass -EndpointsPath.'
    exit 2
}
$endpoints = Get-Content -Raw -Path $EndpointsPath | ConvertFrom-Json

# .NET Framework under 5.1 may offer only SSL3/TLS 1.0 to HttpWebRequest and
# WebClient (speed test, public IP lookup). Add TLS 1.2 without removing
# anything the machine already allows.
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
}
catch { }
Write-Log "SecurityProtocol: $([System.Net.ServicePointManager]::SecurityProtocol)"

$onPixellot = Test-OnPixellot
Write-Log "Running on a Pixellot: $onPixellot"

Write-Host "VPU network check v$ToolVersion" -ForegroundColor Cyan
Write-Host 'Checks whether this network lets a Pixellot stream, update and be supported.'
Write-Host 'It takes about a minute: a few questions, then about 40 seconds of tests.'
if (-not $onPixellot) {
    Write-Host 'For a real answer, plug this computer into the Pixellot''s switch port or VLAN.'
}

$ipConfig = Get-IpConfig
Show-IpConfig $ipConfig
foreach ($r in $ipConfig) {
    Write-Log ("Uplink '{0}': MAC {1}, {2}, IP {3}, mask {4}, gateway {5}, DNS1 {6}, DNS2 {7}" -f
        $r.adapter, $r.mac, $r.addressing, $r.ipAddress, $r.subnetMask, $r.gateway, $r.dns1, $r.dns2)
}

if ($SkipQuestions) {
    $answers = [pscustomobject]@{
        venue = $Venue; pixellotId = $(if ($PixellotId) { $PixellotId } elseif ($onPixellot) { [Environment]::MachineName } else { '' })
        sameVlan = $(if ($onPixellot) { 'self' } else { $null }); dedicatedVlan = $null; rulesConfigured = $null
        speedTest = $(if ($SkipSpeedTest) { 'no' } else { $null })
    }
    Write-Log 'Questions skipped (-SkipQuestions)'
}
else {
    $answers = Invoke-PreTestQuestions $endpoints $onPixellot $Venue $PixellotId ([bool]$SkipSpeedTest)
    if (-not $answers) {
        Write-Log 'Stopped at a question before testing'
        Write-Host 'Stopped before testing. Run it again once the computer is on the Pixellot''s network.'
        exit 3
    }
}
$Venue = $answers.venue
Write-Log "Venue: $Venue  Pixellot ID: $($answers.pixellotId)"

Write-Section 'Checks'
Write-Host "Gathering network context..."
$context = Get-NetContext
$script:Resolver = if ($context.dns) { ($context.dns -split ',\s*')[0] } else { $null }
Write-Log ("Context: connection {0}, local IP {1}, gateway {2}, DNS {3}, public IP {4}" -f $context.connection, $context.localIp, $context.gateway, $context.dns, $context.publicIp)
if ($context.connection -eq 'Wi-Fi') {
    Write-Wrapped 'Note: this computer is on Wi-Fi. A wired connection on the Pixellot''s port gives a more reliable answer.' '' 'Yellow'
}

$results = New-Object System.Collections.Generic.List[object]
function Get-ShortNote($R) {
    # A few words for the console line; the full detail is in the report.
    switch ($R.outcome) {
        'resolved'    { return [string]$R.ip }
        'not-found'   { return 'name not found' }
        'no-address'  { return 'no address' }
        'connected'   { return "open ($($R.elapsedMs) ms)" }
        'reply'       { return 'open (reply)' }
        'timeout'     { return 'dropped (no response)' }
        'no-reply'    { return 'dropped (no reply)' }
        'refused'     { return 'rejected (TCP reset)' }
        'rejected'    { return 'rejected (ICMP)' }
        'unreachable' { return 'no route' }
        'no-dns'      { return 'lookup failed' }
        'trusted'     { return 'trusted certificate' }
        'intercepted' { return 'certificate replaced' }
        'reset'       { return 'cut by a filter' }
        'no-cert'     { return 'no certificate' }
        default {
            if ($R.category -eq 'Speed') {
                if ($R.status -eq 'warn') { return 'could not measure' }
                return ($R.detail -replace ' \(below.*$', '')
            }
            return 'error'
        }
    }
}

$ConsoleTag      = @{ pass = '[ OK ]'; fail = '[FAIL]'; warn = '[WARN]' }
$ConsoleTagColor = @{ pass = 'Green';  fail = 'Red';    warn = 'Yellow' }

function Invoke-Check([string]$Label, $Entry, [scriptblock]$Check) {
    # Runs one check, times it and logs the outcome, so the log shows what
    # happened even when the console has scrolled away. The entry's service,
    # severity and consequence ride along on the result for the verdict.
    # The label prints first and the result lands on the same line when the
    # check finishes, so a 4-second drop reads as "waiting", not a hang.
    if ($Label.Length -gt 42) { $Label = $Label.Substring(0, 41) + '~' }
    Write-Host ("  {0,-42} " -f $Label) -NoNewline
    $startedAt = Get-Date -Format 'HH:mm:ss'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = & $Check
    $sw.Stop()
    $r | Add-Member -NotePropertyName service     -NotePropertyValue $Entry.service
    $r | Add-Member -NotePropertyName severity    -NotePropertyValue $Entry.severity
    $r | Add-Member -NotePropertyName consequence -NotePropertyValue $Entry.consequence
    $r | Add-Member -NotePropertyName elapsedMs   -NotePropertyValue $sw.ElapsedMilliseconds
    # Time of day lets the admin find the matching entry in firewall logs.
    $r | Add-Member -NotePropertyName time        -NotePropertyValue $startedAt
    $r | Add-Member -NotePropertyName domain      -NotePropertyValue $Entry.domain
    $r | Add-Member -NotePropertyName path        -NotePropertyValue $Entry.path
    $r | Add-Member -NotePropertyName ruleId      -NotePropertyValue $Entry.ruleId
    Write-Host $ConsoleTag[$r.status] -ForegroundColor $ConsoleTagColor[$r.status] -NoNewline
    Write-Host (' ' + (Get-ShortNote $r))
    Write-Log ("{0,-5} {1,-45} {2,-4} {3,-8} {4,6} ms  {5,-15} {6,-11} {7}" -f $r.category, $r.target, $r.status.ToUpper(), $r.severity, $sw.ElapsedMilliseconds, $r.ip, $r.outcome, $r.detail)
    $results.Add($r)
}

$runSpeed = [bool]$endpoints.speedTest -and $answers.speedTest -ne 'no'
if ($endpoints.speedTest -and -not $runSpeed) { Write-Log 'Speed test skipped' }
$checkCount = @($endpoints.dns).Count + @($endpoints.ports).Count + @($endpoints.tls).Count + $(if ($runSpeed) { 2 } else { 0 })
$estimate = if ($runSpeed) { 'about 40 seconds' } else { 'about 30 seconds' }
Write-Host "Running $checkCount checks. This takes $estimate."
Write-Host ''
Write-Host 'Name lookups (DNS)'
foreach ($e in $endpoints.dns)   { Invoke-Check $e.host $e { Test-Dns $e } }
Write-Host ''
Write-Host 'Ports'
foreach ($e in $endpoints.ports) { Invoke-Check ("{0} {1,-5} {2}" -f $e.protocol, $e.port, $e.host) $e { Test-Port $e } }
Write-Host ''
Write-Host 'HTTPS and SSL inspection'
foreach ($e in $endpoints.tls)   { Invoke-Check $e.host $e { Test-Tls $e } }
if ($runSpeed) {
    Write-Host ''
    Write-Host "Speed (at least $($endpoints.speedTest.minMbps) Mbps each way)"
    foreach ($dir in 'Download', 'Upload') {
        Invoke-Check $dir $endpoints.speedTest { Test-Speed $endpoints.speedTest $dir }
    }
}

# Supplemental, not a check: the current addresses behind each required
# domain, for firewalls that take IPs instead of names.
$addresses = @()
if ($endpoints.requirements.rules) {
    Write-Host ''
    Write-Host 'Looking up current IP addresses for the report'
    $addresses = @(Get-DomainAddresses $endpoints)
    $addressTime = Get-Date -Format 'HH:mm'
}

# A skipped speed test is listed with what this tool can't test, so the
# report doesn't read as if speed was confirmed.
$notTested = @($endpoints.notTested)
if ($endpoints.speedTest -and -not $runSpeed) {
    $min = $endpoints.speedTest.minMbps
    $notTested = @([pscustomobject]@{
        item = "Speed: at least $min Mbps download and $min Mbps upload"
        why  = 'The speed test was skipped for this run. Confirm the Pixellot''s connection has this another way, or run the check again and answer Y to the speed test.'
    }) + $notTested
}

$failed = @($results | Where-Object { $_.status -eq 'fail' }).Count
$warned = @($results | Where-Object { $_.status -eq 'warn' }).Count
$verdict = Get-Verdict $results.ToArray() $endpoints.services
$ruleSheet = @(Get-RuleSheet $endpoints.requirements.rules $results.ToArray())
$report = [pscustomobject]@{
    toolVersion = $ToolVersion
    venue       = $Venue
    timestamp   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    context     = $context
    ipConfig    = $ipConfig
    answers     = $answers
    verdict     = $verdict
    notTested   = $notTested
    patternNote = $endpoints.patternNote
    docUrl      = $endpoints.docUrl
    rules       = $ruleSheet
    rulesCsv    = [System.IO.Path]::GetFileName($csvPath)
    addresses   = $addresses
    addressInfo = [pscustomobject]@{ time = $addressTime; resolver = $script:Resolver }
    summary    = [pscustomobject]@{ total = $results.Count; failed = $failed; warned = $warned }
    results     = $results.ToArray()
}
Write-Log "Summary: $($results.Count) checks, $failed failed, $warned warnings"
Write-Log "Verdict: $($verdict.headline)"
foreach ($s in $verdict.services) { Write-Log ("  {0,-5} {1}: {2}" -f $s.status.ToUpper(), $s.name, $s.summary) }

[System.IO.File]::WriteAllText($jsonPath, ($report | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
Write-RuleCsv $ruleSheet $csvPath
Write-HtmlReport $report $htmlPath
Write-Log "Report: $htmlPath"
Write-Log "Rules:  $csvPath"
Write-Log "Data:   $jsonPath"

# ---- console summary: verdict, services, changes, next steps --------------
# Everything wraps at 78 columns so it reads in a default cmd.exe window
# (80 wide) without lines breaking mid-word. Status is always a bracketed
# word as well as a color, so it survives copy-paste into an email.

$verdictColor = @{ 'not-ready' = 'Red'; 'issues' = 'Yellow'; 'ready' = 'Green' }[$verdict.state]
$svcTag = @{ ok = '[ OK ]'; fail = '[FAIL]'; check = '[WARN]' }
$svcTagColor = @{ ok = 'Green'; fail = 'Red'; check = 'Yellow' }

Write-Section 'Result'
Write-Wrapped $verdict.headline.ToUpper() '' $verdictColor
Write-Wrapped $verdict.detail
Write-Host ''
Write-Host 'What works on this network'
foreach ($s in $verdict.services) {
    Write-Host '  ' -NoNewline
    Write-Host $svcTag[$s.status] -ForegroundColor $svcTagColor[$s.status] -NoNewline
    if ($s.status -eq 'ok') {
        Write-Host (" {0,-30} {1}" -f $s.name, $s.summary)
    }
    else {
        Write-Host " $($s.name)"
        Write-Wrapped $s.summary '         '
    }
}

$changes = Get-ChangeGroups $results.ToArray() $endpoints.services
if ($changes) {
    Write-Host ''
    Write-Host $(if ($verdict.state -eq 'issues') { 'Items to check' } else { 'Changes needed, most severe first' })
    $n = 0
    foreach ($g in $changes) {
        # Each change wraps over several lines, so a gap keeps them apart.
        if ($n -gt 0) { Write-Host '' }
        $n++
        $sevColor = if ($g.rank -eq 0) { 'Red' } elseif ($g.rank -eq 1) { 'Yellow' } else { 'Gray' }
        Write-Host ("  {0}. " -f $n) -NoNewline
        Write-Host "[$($g.severity)]" -ForegroundColor $sevColor -NoNewline
        Write-Host " $($g.affects)"
        Write-Wrapped $g.fix '     '
    }
}

$steps = @()
if ($changes) {
    $steps += 'Open the full report for the evidence behind each change: the IP addresses tried, the times (to match your firewall logs) and certificate details.'
    $steps += 'After making the changes, run Run-PulseVerify.bat again.'
}
if ($endpoints.speedTest -and -not $runSpeed) {
    $steps += "The speed test was skipped. The Pixellot needs at least $($endpoints.speedTest.minMbps) Mbps download and upload; confirm this another way."
}
$steps += "The firewall rule sheet, with this run's result for each rule, is in the report and saved as $([System.IO.Path]::GetFileName($csvPath)) to import or forward."
if ($addresses) {
    $steps += 'If the firewall needs IP addresses instead of domain names, the report lists the current addresses for each domain.'
}
if ($steps) {
    Write-Host ''
    Write-Host 'Next steps'
    foreach ($s in $steps) { Write-Wrapped $s '    ' '' '  - ' }
}
Write-Host ''
Write-Host 'Report saved to:'
Write-Host "  $htmlPath"
Write-Host ''

exit ([int]($verdict.state -eq 'not-ready'))
