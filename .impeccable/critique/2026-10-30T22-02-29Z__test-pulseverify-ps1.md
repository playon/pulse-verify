---
target: pulse-verify HTML report and cmd.exe output (v0.8.0 re-critique)
total_score: 29
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 2
target_identity: "file:/Users/ian.moore/Code/pulse-verify/Test-PulseVerify.ps1"
target_fingerprint: "sha256:3c415df1f433b44b46bfb9950ad4545ba7a4acffe39659491a215c65d5897a66"
target_path: /Users/ian.moore/Code/pulse-verify/Test-PulseVerify.ps1
timestamp: 2026-10-30T22-02-29Z
slug: test-pulseverify-ps1
---
Method: dual-agent (A: design review, B: detector + browser)
Target: pulse-verify v0.8.0 HTML report and cmd.exe output. Fixtures: VPU2 failing fixture, VPU2 real run (speed rate-limited), Mac all-pass; bat console transcript.

## Design Health Score: 29/40 (Good), was 19/40
1 Visibility 3; 2 Real world 3 (VPU vs Pixellot); 3 Control 3; 4 Consistency 2 (OK/PASS/[ OK ], WARN/Check; 5 problems vs 4 changes); 5 Error prevention 3 (wildcard UDP advice); 6 Recognition 3 (ports/domains two lists); 7 Efficiency 3 (no rule export); 8 Minimalism 3; 9 Error recovery 3 (speed copy); 10 Help 3 (no Next steps in HTML)

## Detector
CLI clean on all 3 reports (+layout scope). Live detect.js: nested-cards (services table in verdict, false positive), line-length ~148 footer filenames (ignore), line-length ~99 on two ledes (minor), straggler (cosmetic). Measured: lang/viewport/scope 39/39/heading outline OK; contrast all AA (min 6.03); no mobile overflow; print opens all details; services table 0/14 data-labels; details stay open after print.

## Priority issues
- [P1] Headline counts failed probes (5) not change groups (4); a speed "Check" sits in Changes needed. Fix: "N changes to make (and M items to check)", separate Items-to-check table under Not ready, same in console. /impeccable clarify
- [P1] Rules not firewall-ready: wildcard FQDN for UDP impossible on Palo Alto; ports and domains are separate lists. Fix: single rule sheet (proto, port, destination, needed for, tested, this run) + fallback note (wording NFHS's call) + optional CSV. /impeccable clarify, harden
- [P2] Status vocabulary/color drift; High shares amber with WARN. Fix: one word per state; High in red family; amber only non-blocking. /impeccable colorize, polish
- [P2] Speed/ready-with-items copy: "Speed Download speed", rate limit under Live streaming WARN, console Next steps mention changes when none. /impeccable clarify
- [P2] HTML lacks Next steps; evidence prose hard to match to logs (no source/NAT IP, no timezone, SHA-1 wraps); no 8.8.8.8 comparison on DNS failure. /impeccable layout, clarify

## Personas
Jordan: VPU undefined; no forward-to-admin line; no severity legend; on-Pixellot note after ID prompt. Sam: summary flex removes disclosure triangle; services table lacks mobile labels; 12-13px secondary. Dana: two lists not triples; no PAN path; no source/NAT IP per failure; no TZ; 5 vs 4; reset source wording.

## Minor
"All 2 checks"; meta repeats unit; "(cached)"; column widths vary across groups; print leaves details open; ~99ch ledes.
