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

### Added

- **Fortinet FortiClient** conflict signature (Risk: High) — detects `fortifilter`, `fortiwf`, `fortissl`, `fortivpn`, `fortidrv` drivers and `FortiClient` / `FortiWF` services.
- **Ivanti Secure Access / Pulse Secure** conflict signature (Risk: High) — detects `jnprns`, `dsNcAdpt`, `pulse`, `pulsesecure`, `ivanti` drivers and `PulseSecureService` / `Ivanti Secure Access` / `dsNcService` services.
- **F5 BIG-IP Edge Client** conflict signature (Risk: High) — detects `f5vpn`, `f5ndis`, `f5fpclient` drivers and `BIG-IP Edge Client` / `F5 Networks VPN Service` services.
- **SonicWall NetExtender** conflict signature (Risk: High) — detects `sonicwall`, `netextender`, `nxdrv`, `swvnic` drivers and `NetExtender` / `SONICWALL_NetExtender` services.
- **Sophos Connect / Sophos ZTNA** conflict signature (Risk: High) — detects `sophos`, `sophosnetfilter`, `sophosztna` drivers and `Sophos Connect Service` / `Sophos ZTNA` / `Sophos Network Threat Protection` services.
- **Absolute Secure Access / NetMotion** conflict signature (Risk: High) — detects `netmotion`, `nmfilter`, `nmdrv`, `mobility` drivers and `NetMotion Mobility Client` / `Absolute Secure Access` services.
- **Appgate SDP** conflict signature (Risk: High) — detects `appgate`, `appgatesdp`, `agtun` drivers and `Appgate SDP Client` / `Appgate SDP Service` services.
- **Akamai Enterprise Application Access** conflict signature (Risk: Medium) — detects `akamai`, `eaa`, `akamaiaccess` drivers and `Akamai EAA Client` / `EAAClient` services.
- **Twingate** conflict signature (Risk: Medium) — detects `twingate`, `wintun` drivers and `Twingate` / `Twingate Service` services.
- Renamed `Palo Alto Prisma` → `Palo Alto Prisma / GlobalProtect` for clarity.
- Reorganized `$KnownVendors` with category comments (CASB/SWG/SSE, Palo Alto, Cisco, Citrix, Fortinet, Ivanti, F5, SonicWall, Sophos, Absolute/NetMotion, Appgate, Akamai, ZTNA, Endpoint Security, VPN, Traffic Shaping).
- Vendor count bumped from 23 to **32**.

---

## [1.2.0] — 2026-06-09

### Added

- **Cisco Secure Client / AnyConnect VPN** conflict signature (Risk: High) — replaces former "Cisco AnyConnect" entry; expands drivers to include `vpnva64`, `acnamfd`, `acwfp` and services to include `acvpnagent` / `Cisco Secure Client`. Elevated to High risk.
- **Cisco Secure Client – Umbrella Module** conflict signature (Risk: High) — detects `acumbrella`, `acwfp`, `csc_umbrella`, `umbrella` drivers and `csc_umbrellaagent` / `Umbrella_RC` services. DNS-layer interception conflicts with GSA private access resolution.
- **Cisco Umbrella Roaming Client** conflict signature (Risk: High) — detects `umbrella`, `opendns`, `acumbrella` drivers and `Umbrella_RC` / `OpenDNS_Connector` services. Loopback DNS redirect conflicts with GSA DNS steering and private app discovery.
- **Cisco Secure Endpoint** conflict signature (Risk: Medium) — detects `ciscoamp`, `amp`, `sfc`, `immunetprotect`, `orbital` drivers and `CiscoAMP` / `Cisco Secure Endpoint` services. Network inspection or isolation policy may affect GSA tunnel traffic.
- **Cisco Secure Access** conflict signature (Risk: High) — detects `ciscosecureaccess`, `ciscoztna`, `acwfp`, `acvpnwfp` drivers and `Cisco Secure Access` / `CiscoSecureAccess` / `csc_svr` services. Cisco's SSE/ZTNA client directly overlaps with GSA for traffic steering and private access.
- **Cisco AnyConnect NVM** conflict signature (Risk: Low) — detects `acnvm`, `acnamfd`, `acsock` drivers and `acnvmagent` / `Cisco AnyConnect NVM` / `Cisco Secure Client NVM` services. Primarily telemetry; low conflict risk but surfaced for coexistence visibility.
- **Citrix Secure Access / NetScaler Gateway** conflict signature (Risk: High) — detects `nsgwfp`, `nswfp`, `nsload`, `dne`, `deterministicnetworkenhancer`, `citrixvpn`, `ctxvpn` drivers and `Citrix Secure Access` / `Citrix Gateway Plugin` / `nsgateway` / `ctxvpn` services. WFP/DNE drivers used for split-tunnel and traffic interception overlap with GSA traffic steering and private access classification.
- Added `AGENTS.md` single-source maintenance guide for AI agents and contributors.
- `CONTRIBUTING.md`: corrected vendor schema, added `vendorRemediation` step, linked `docs/add-vendor.md`.
- `Get-GSAConflictReport.ps1`: added `$script:Version` constant, startup console banner, `toolVersion` in report META, version shown in HTML report header.
- `docs/user-guide.html`: corrected vendor list to match script; bumped badge to v1.2.
- Vendor count bumped from 17 to **23**.
