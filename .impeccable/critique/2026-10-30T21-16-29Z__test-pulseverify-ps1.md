---
target: pulse-verify HTML report and cmd.exe output
total_score: 19
max_score: 40
na_heuristics: 
p0_count: 1
p1_count: 2
target_identity: "file:/Users/ian.moore/Code/pulse-verify/Test-PulseVerify.ps1"
target_fingerprint: "sha256:ae5358c3196836c8ef58399f42064a8bb2f5fa5596da05c721edee6de5e58f17"
target_path: /Users/ian.moore/Code/pulse-verify/Test-PulseVerify.ps1
timestamp: 2026-10-30T21-16-29Z
slug: test-pulseverify-ps1
closed: true
---
Method: dual-agent (A: design review, B: detector + browser)
Target: pulse-verify HTML report (Write-HtmlReport) and cmd.exe console output, Test-PulseVerify.ps1 v0.2.0. Fixture: VPU2 run under PS 5.1 with 6 simulated blocks; answered not-same-VLAN.

## Design Health Score: 19/40 (Poor)
1 Visibility 2 (console prints labels before checks, silent 4 s stalls, results dumped at end)
2 Real world 2 (tester vocabulary, not firewall vocabulary)
3 Control 2 (no rerun guidance, no rerun-failed)
4 Consistency 2 (pass/PASS; 7 requirement rules never map to 33 probe rows)
5 Error prevention 2 (VLAN/Wi-Fi guards good; "configured: Yes" vs failures never reconciled)
6 Recognition 1 (rules shown 19 lines above question; failures not linked to requirement)
7 Efficiency 2 (JSON/log never mentioned; no paste-able rules)
8 Minimalism 2 (6 fails among 26 passes; Fix column empty 26/32)
9 Error recovery 2 (good fix copy, no severity, duplicated TLS sentence)
10 Help 2 (doc URL console-only; no support contact in report)

## Design specificity
Generic test-results table in probe order. endpoints.json knows "either UDP path alone is a healthy stream" but verdict ignores it. Detector: flat-type-hierarchy in both reports, false positive (rendered 32/24/16); live detect.js "No anti-patterns found". Measured: no viewport meta (980 px layout at 375), no lang/thead/caption/scope/landmarks, no print or dark CSS; contrast passes AA.

## Priority issues
- [P0] No severity/impact/failover model; "NOT READY: 6 required check(s) failed" treats degraded-but-streaming like dead. Fix: impact+severity in endpoints.json, failover evaluation, three-state verdict, per-service status strip. /impeccable clarify
- [P1] "Changes needed" not firewall-ready; UDP 2088/443 fix says "any destination" but NFHS doc says use *.pixellot.stream domain rules; TCP 1935 fix has no destination; 10054 reject collapsed into drop; IPs/timestamps log-only; TLS shows issuer short name only. Fix: rule table grouped by requirement with evidence; "Not tested" list. /impeccable harden
- [P1] Console: no inline results, 200-wide Format-Table wraps in conhost, lowercase fail, ends on Temp paths. Fix: [ OK ]/[FAIL] per line as it runs, run-length line, failures-only summary at 78 cols, next-steps block. /impeccable distill
- [P2] Report IA/mobile/a11y/print: flat 6-col table, red caveat styled as verdict, IP config at bottom, identical titles, "every check passed" over-claims. Fix: verdict > service strip > rule table > neutral run-context box > collapsed passes; viewport, lang, thead/caption/scope; descriptive title; print CSS. /impeccable layout
- [P2] Pre-test flow jargon, no "not sure", rules list scrolls away, answers never reconciled, venue "2". /impeccable onboard

## Personas
Jordan: can't answer VLAN Qs; DPI jargon; silent stalls look like hang; ends on Temp paths. Sam: no lang/viewport/table semantics; result is 4th cell; "->" read aloud; wrapped console table. Dana: no 1935 destination; drop vs reject hidden; no IPs/times; no cert thumbprint; resolver not stated; maps 7 wildcards to 33 rows herself.

## Minor
DNS 2 blank; "in 0 ms"; check(s) plural; public IP silent fail; speed method unnamed; skip VLAN Q on VPU; dark mode deliberate.

## Questions
Ready-on-backup-path? Paste-able firewall objects? Collapse passes per service? Console verdict-only?
