# pulse-verify

A pre-deployment network check for venue IT teams. Run it before the VPU
arrives to confirm the firewall rules from the NFHS Network firewall article
are actually in place.

It runs the same probes Pulse runs on a live VPU (ported from
`playon/pulse` `Pulse.Web/scripts/`), so a pass here means the same as a pass in
Pulse.

## For IT teams

Download [`pulse-verify.zip`](https://github.com/playon/pulse-verify/releases/latest/download/pulse-verify.zip)
from the latest release. The same steps ship in the zip as `README.txt`.

1. Plug a Windows laptop into the **same network segment the VPU will use**
   (same VLAN, same switch port profile, same firewall policy). Guest Wi-Fi or
   a staff VLAN will give you the wrong answer.
2. Unblock the zip (right-click, Properties, tick **Unblock**), unzip it and
   double-click `Run-PulseVerify.bat`. If Windows says the publisher could
   not be verified, click **Run**; if it says "Windows protected your PC",
   click **More info**, then **Run anyway**.
   **Note:** the tool first shows this computer's IP configuration. Verify it
   matches the Pixellot's network (IP range, gateway, DNS) before continuing
   with the test.
3. Answer the questions: whether this computer is on the Pixellot's VLAN,
   whether the Pixellot has its own VLAN, whether to review the NFHS Network
   firewall article (yes opens it in your browser), whether the firewall
   rules are set up, and whether to run the speed test. Answer `?` if you are not sure; the
   report notes it. On a Pixellot itself, the VLAN question is skipped.
4. The report opens in your browser. It starts with a verdict (**Ready**,
   **Ready, with items to check**, or **Not ready**) and a line per service.
   Fix anything under **Changes needed**, starting at row 1, then run it again.

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

The report also has a **firewall rule sheet**: one row per rule the Pixellot
needs (protocol, port, destination, priority, whether to exempt it from SSL
inspection), what to do if the firewall can't use wildcard domains, and this
run's result for each rule. The same sheet is saved next to the report as
`vpu-network-check-<time>-rules.csv`, to import or forward to whoever manages
the firewall.
