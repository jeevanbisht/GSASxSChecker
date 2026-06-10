# Changelog

All notable changes to **GSA SxS Checker** will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-01-15

### Added

- **Initial release** of `Get-GSAConflictReport.ps1`
- Kernel-mode WFP callout driver detection via `Win32_SystemDriver` (WMI)
- Live WFP engine dump via `netsh wfp show state` (requires Administrator elevation)
- 12 vendor conflict signatures: Forcepoint, Check Point, Skyhigh, Zscaler, Netskope, Palo Alto Networks, CrowdStrike Falcon, SentinelOne, Broadcom/Symantec, Trend Micro, Cisco Umbrella, Sophos
- GSA Client detection: version, install date, service status, tunnel channel health (M365 / Internet / Private / Entra)
- Entra ID join type detection via `dsregcmd /status` (Entra ID / Hybrid / On-prem / Workgroup)
- System information collection: identity, OS (DisplayVersion, UBR, Edition), hardware (CPU, RAM, Disk), runtime (PowerShell, .NET), network adapters
- Self-contained interactive HTML report (6 tabs): Summary, Findings, WFP Details, Kernel Drivers, System Info, Remediation
- Risk scoring banner: None / Low / Medium / High
- Dark / light mode toggle (auto-detects OS preference)
- `-OutputPath` parameter for custom report path
- `-NoBrowser` switch to suppress auto-opening the report
- Comment-based help (accessible via `Get-Help .\Get-GSAConflictReport.ps1 -Full`)
- Professional documentation: README.md, CONTRIBUTING.md, docs/user-guide.html

---

## [1.1.0] — 2026-06-09

### Added

- **OpenVPN** conflict signature (Risk: Medium) — detects `ovpn-dco`, `tap_ovpnconnect`, `tapwindows`, `ovpnco` kernel drivers and `OpenVPNService` / `OpenVPN Connect` services. OpenVPN's TAP/DCO tunnel driver uses WFP and can conflict with GSA traffic steering at the redirect layer.
- **WireGuard** conflict signature (Risk: Medium) — detects `wintun`, `WireGuard` kernel drivers and `WireGuardTunnel` / `WireGuardManager` services. The Wintun kernel driver registers WFP callouts for tunnel traffic that can conflict with GSA network interception.
- **Cloudflare One** conflict signature (Risk: High) — detects `CloudflareWARP` / `WARP` / `warp-svc` services and `cfwfpco` / `cfwfp` kernel drivers. Cloudflare One Client is a competing ZTNA/SASE agent that intercepts and tunnels network traffic at the same WFP layers as GSA. Note: the client runs as a user-mode service; detection is via `Get-Service` rather than `Win32_SystemDriver`.
- **Tailscale** conflict signature (Risk: Medium) — detects `Tailscale` / `tailscaled` services and `wintun` / `tailscale` kernel drivers. Uses the Wintun kernel driver (shared with WireGuard) and registers WFP callouts for its mesh VPN tunnel. Coexistence depends on destination routing configuration.
- **NetLimiter** conflict signature (Risk: Medium) — detects `nldrv` / `netlimiter` kernel drivers and `nlsvc` / `NetLimiter` services. NetLimiter installs a true kernel-mode WFP driver (`nldrv.sys`, signed by Locktime Software s.r.o.) to shape and monitor per-application traffic, which may interfere with GSA tunnel classification.
- All five new signatures confirmed detected on a test machine.
- Added vendor onboarding guide (`docs/add-vendor.md`) as the canonical step-by-step reference for contributors.

### Changed

- Vendor count updated from 12 to **17** in README and detection pipeline description.
- `docs/user-guide.html` vendor list and version badge updated to reflect v1.1 additions.

---

## [Unreleased]

_(New entries go here during development)_
