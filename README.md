# pulse-verify

A pre-deployment network check for venue IT teams. Run it before the VPU
arrives to confirm the firewall rules from the NFHS Network firewall article
are actually in place, and send the report to NFHS Network support.

It runs the same probes Pulse runs on a live VPU (ported from
`playon/pulse` `Pulse.Web/scripts/`), so a pass here means the same as a pass in
Pulse.

## For IT teams

1. Plug a Windows laptop into the **same network segment the VPU will use**
   (same VLAN, same switch port profile, same firewall policy). Guest Wi-Fi or
   a staff VLAN will give you the wrong answer.
2. Unzip this folder and double-click `Run-PulseVerify.bat`.
   **Note:** the tool first shows this computer's IP configuration. Verify it
   matches the Pixellot's network (IP range, gateway, DNS) before continuing
   with the test.
3. Answer the questions: venue, the Pixellot ID from its label (optional),
   whether this computer is on the Pixellot's VLAN, whether the Pixellot has
   its own VLAN, whether the firewall rules are set up, and whether to run the
   speed test. Answer `?` if you are not sure; the report notes it. On a Pixellot itself, the VLAN question
   is skipped and the ID defaults to the computer name.
4. The report opens in your browser. It starts with a verdict (**Ready**,
   **Ready, with items to check**, or **Not ready**) and a line per service.
   Fix anything under **Changes needed**, starting at row 1, then run it again.
5. Send the `.html` report from the `reports` folder to NFHS Network support
   at help.nfhsnetwork.com. Next to it is a `.json` copy of the results, and
   the `logs` folder has a `.log` file with timings and errors, which support
   may ask for.

No install and no admin rights needed. It makes outbound connections only.

## What it checks

| Check | Why |
|---|---|
| IP configuration | Shown first: MAC, DHCP or static, IP, subnet mask, gateway, DNS 1 and 2 for the internet-facing adapter only (camera ports and VPNs are left out). Not a pass/fail check. |
| DNS | The required domains resolve through the venue's resolver. |
| UDP 53 to 8.8.8.8 | The Pixellot's default DNS server is reachable. |
| balenaOS (Linux units) | TLS to Balena's published hosts, TCP 443 to the cloudlink tunnel. |
| TCP 443 | Pixellot cloud, NFHS Network, Singular overlays, LogMeIn. |
| UDP 2088 / 443 | Zixi streaming. Must get an echo reply, since a silent drop is the most common block. |
| UDP 123 | Time sync. |
| TCP 1935 | RTMP fallback. |
| Speed | Optional. At least 10 Mbps download and upload (about 20 s, via speed.cloudflare.com). Skip it on a metered or busy connection; the report then shows the speed test as skipped. |
| TLS inspection | Catches firewalls that substitute their own certificate. Video can stream while Singular graphics fail. |

The full list lives in [`endpoints.json`](endpoints.json).

When something fails, the report's **Changes needed** table lists one row per
firewall change, most severe first. Each row shows the evidence behind it:
the IP address tried, whether the traffic was silently dropped or actively
rejected, the time (to match firewall logs), and for SSL inspection the
replacement certificate's subject, issuer, root, SHA-1 thumbprint and likely
vendor. Requirements the tool can't test (for example `*.pixellot.stream`,
which only exists during events) are listed at the end.

## For developers

- `endpoints.json` is the single source of truth for domains and ports.
  The goal is for Pulse's `Test-Network*.ps1` scripts and the customer docs to
  read this file too, so they can't drift apart.
- `Test-PulseVerify.ps1` must run on **Windows PowerShell 5.1** and follow the
  portability rules in pulse's `CLAUDE.md`: ASCII only, explicit delegate casts,
  pinned `SslProtocols`, `[pscustomobject]` rows.
- It also runs under `pwsh` on macOS for development. Network-context fields
  (gateway, DNS) are blank there.

```bash
pwsh ./Test-PulseVerify.ps1 -SkipQuestions -Venue "Dev test" -OutDir /tmp
```

Exit code is `0` when the verdict is Ready (with or without items to check),
`1` when it is Not ready (any critical or high failure), `2`
when `endpoints.json` is missing, `3` when the person stopped at a
question, and `4` on an unexpected error (details in the `.log`). Pass `-SkipQuestions` (with optional `-Venue` and `-PixellotId`) for scripted or remote runs, and `-SkipSpeedTest` to leave out the speed test.

`endpoints.json` holds:

- `requirements`: the rules IT is asked to allow, copied from the NFHS
  firewall article. Shown in the report as-is.
- `dns`, `ports`, `tls`, `speedTest`: the probes, which are how those rules
  are tested. Each probe has a `service` (what breaks), a `severity`
  (`critical` or `high`, from the article's impact ratings), the requirement
  `domain` its fix names, and optionally a `rule` and a `consequence`.
- `services`: the order and plain-language names used in the verdict.
- `patternNote`: shown in the report.
- `notTested`: written to the results JSON only.

After the checks, the tool looks up the current IPv4 addresses of every probe
host under each `requirements.domains` entry and lists them in the report
(and as `addresses` in the JSON), for firewalls that take IPs instead of
names. This is supplemental and never affects the verdict.

The verdict is **Not ready** when any critical or high probe fails,
**Ready, with items to check** when only warnings remain (for example the
speed test site could not be reached), and **Ready** otherwise.

## TODO

- [x] Name the inspection vendor from a replaced certificate's issuer.
- [ ] Port `Get-FilterBlockSignal` from `Test-TlsInspection.ps1` to name the
      filter vendor when HTTPS is reset outright (no certificate to read).
- [ ] Speed test: a single connection to speed.cloudflare.com, which
      rate-limits repeated runs (reported as an item to check). Consider a
      second provider or multiple streams.
- [ ] Have Pulse read `endpoints.json` instead of its hardcoded lists.
- [ ] Generate the customer-facing domain/port doc from `endpoints.json`.
- [ ] Packaging: a signed zip, or a single `.ps1` with the JSON embedded.
- [ ] Optional: upload the report to PlayOn so support sees results without
      waiting for an email.
