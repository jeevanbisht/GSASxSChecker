# Changelog

All notable changes to **GSA SxS Checker** will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.7.0] — 2026-06-13

### Added

- **`-ShowAll` switch** — includes low-confidence (driver-only) matches in the Detected Conflicts and Findings views. By default only high-confidence (service-matched) conflicts are shown.

### Changed

- **Detected Conflicts now default to confirmed conflicts only** — the Summary table, Findings tab, count badge, overall risk banner, and console summary all count only conflicts where a vendor service name actually matched on the machine (Match = Yes). Low-confidence driver-only matches are hidden unless `-ShowAll` is passed, with a note indicating how many were hidden.
- Console summary and `findingCount` now reflect confirmed conflicts only, consistent with the report.

### Removed

- **Private Internet Access** vendor signature removed; vendor count adjusted to 58.

---

## [1.6.0] — 2026-06-11

### Added

- **VMware Workspace ONE Tunnel** (Risk: High) — enterprise per-app VPN and secure access
- **BeyondTrust Secure Remote Access** (Risk: Medium) — Bomgar-based remote access networking
- **NordVPN** (Risk: Medium) — NordLynx/WireGuard consumer VPN
- **ExpressVPN** (Risk: Medium) — consumer VPN with DNS/route ownership
- **Surfshark** (Risk: Medium) — WireGuard-based consumer VPN
- **Private Internet Access** (Risk: Medium) — WireGuard/OpenVPN consumer VPN
- **Proton VPN** (Risk: Medium) — WireGuard-based VPN with DNS interception
- **Mullvad VPN** (Risk: Medium) — WireGuard-based privacy VPN
- **Cita VPN** (Risk: Medium) — consumer VPN with tunnel route ownership
- Vendor count bumped to 59

---

## [1.5.0] — 2026-06-11

### Added

- **Cato Networks** vendor signature (Risk: High) — detects `cato`, `catovpn`, `catotunnel`, `catowfp` kernel drivers and `CatoClient`, `CatoNetworks`, `CatoVPN` services
- Vendor count bumped to 50

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

---

## [1.4.3] — 2026-06-10

### Fixed

Comprehensive audit of all service and driver patterns — removed every short (≤4 char) or generic substring pattern that could produce false positives via `*pattern*` wildcard matching:

**Service patterns removed:**
- `"cpd"` from Check Point — could match `AMDCPDService` (AMD Crash Prevention Device) and similar
- `"amon"` from Check Point — short/generic, collision risk with unrelated monitoring agents
- `"Orbital"` from Cisco Secure Endpoint services — replaced with `"CiscoOrbital"` (more specific)
- `"amp"` from Cisco Secure Endpoint drivers — 3-char pattern, high collision risk with unrelated drivers

**Driver patterns removed:**
- `"amp"` from Cisco Secure Endpoint — 3 chars, matches any driver/component containing "amp"
- `"sfc"` from Cisco Secure Endpoint — could match Windows system components
- `"via"` from Aruba VIA — matches VIA Technologies chipset drivers (`viaXxx.sys`)
- `"epp"` from CoSoSys Endpoint Protector — 3-char generic EPP acronym
- `"dsp"` from ManageEngine DataSecurity Plus — 3-char generic acronym
- `"shield"` from Ericom Shield — generic word, collision risk with other security products
- `"eaa"` from Akamai EAA — 3-char acronym, matches unrelated drivers

---

## [1.4.2] — 2026-06-10

### Fixed

- **Cloudflare One false positive**: removed the bare `"WARP"` service pattern which matched the Windows built-in **Warp JIT Service** (WinAppSDK MSIX JIT) via `*WARP*` substring. Detection is now scoped to `CloudflareWARP` and `warp-svc` only, which are exclusive to the Cloudflare WARP client.

---

## [1.4.1] — 2026-06-10

### Fixed

- **Open Systems SASE false positive**: removed the 3-character driver pattern `"ose"` which matched AMD audio kernel drivers (e.g. AMDAcpBtAudioService, AtiHDAudioService) via substring wildcard. Driver detection is now scoped to `opensystems` and `osevpn` patterns only.

---

## [1.4.0] — 2026-06-10

### Added

- **Perimeter 81** (Risk: High) — detects `perimeter81`, `p81`, `wintun` drivers and `Perimeter81` / `Perimeter81Service` services. ZTNA/VPN tunnels overlap with GSA traffic steering.
- **NordLayer** (Risk: High) — detects `nordlayer`, `nordlynx`, `wintun` drivers and `NordLayer` / `NordLayerService` services. Business ZTNA/VPN with route ownership may conflict with GSA.
- **Keeper Connection Manager** (Risk: Medium) — detects `keeper`, `keeperztna` drivers and `Keeper` / `KeeperConnectionManager` services. ZTNA capabilities may overlap with GSA private access.
- **Open Systems SASE** (Risk: High) — detects `opensystems`, `ose`, `osevpn` drivers and `OpenSystems` / `OpenSystemsAgent` services. Managed SASE client with traffic steering.
- **Barracuda VPN** (Risk: High) — detects `barracuda`, `barracudavpn` drivers and `BarracudaVPN` / `Barracuda Network Access Client` services. VPN tunnel ownership conflicts with GSA routing.
- **WatchGuard Mobile VPN** (Risk: High) — detects `wgvpn`, `watchguardvpn` drivers and `WatchGuard Mobile VPN` / `WGVPN` services. SSL/IPsec VPN route ownership.
- **Array Networks VPN** (Risk: Medium) — detects `arrayvpn`, `agsslvpn` drivers and `Array Networks SSL VPN` / `ArrayVPN` services. Enterprise SSL VPN client.
- **Aruba VIA** (Risk: Medium) — detects `arubavia`, `via` drivers and `Aruba VIA` / `ArubaVIAService` services. Virtual adapters and routing may conflict with GSA.
- **Digital Guardian** (Risk: High) — detects `dgflt`, `dgwfp`, `dgagent` drivers and `DgService` / `DigitalGuardian` services. Kernel DLP filtering may interfere with GSA traffic processing.
- **Proofpoint Endpoint DLP** (Risk: Medium) — detects `proofpoint`, `ppwfp` drivers and `Proofpoint` / `Proofpoint Endpoint` services. Network monitoring may affect GSA classification.
- **CoSoSys Endpoint Protector** (Risk: Medium) — detects `epp`, `endpointprotector` drivers and `EndpointProtector` / `EPPService` services. Endpoint DLP with network controls.
- **ManageEngine DataSecurity Plus** (Risk: Low) — detects `dsp`, `manageengine` drivers and `DataSecurityPlus` service. Monitoring/inspection; generally coexists but should be inventoried.
- **Menlo Security** (Risk: Medium) — detects `menlo`, `menlofilter` drivers and `MenloSecurity` / `MenloAgent` services. Isolation and SWG functions may affect traffic steering.
- **Ericom Shield** (Risk: Medium) — detects `ericom`, `shield` drivers and `EricomShield` / `ShieldAgent` services. Browser isolation may overlap with GSA internet access routing.
- **ZeroTier** (Risk: Medium) — detects `zerotier`, `ztvirtual` drivers and `ZeroTierOne` service. Overlay network virtual adapters and route injection may conflict with GSA.
- **NetBird** (Risk: Medium) — detects `netbird`, `wintun` drivers and `NetBird` / `NetBirdService` services. WireGuard-based mesh VPN using Wintun.
- **Headscale** (Risk: Low) — detects `wintun` driver and `Headscale` service. Tailscale-compatible Wintun deployments; generally low risk but inventoried.

### Changed

- Vendor count bumped from **32 → 49** in README and detection pipeline description.
- `$script:Version` and `.NOTES` updated to `1.4.0`.
- `docs/user-guide.html` vendor list updated with 17 new vendor chips.
- `.DESCRIPTION` header updated to list all new vendor names.

---

## [1.3.3] — 2026-06-09

### Changed

- All 7 vendor remediation entries that have an official Microsoft Learn coexistence guide now use a concise one-liner + clickable `<a href>` link to the doc, replacing the verbose inline step-by-step text: Palo Alto Prisma/GlobalProtect, Zscaler, Netskope, Cisco Secure Client/AnyConnect VPN, Cisco Secure Client – Umbrella Module, Cisco Umbrella Roaming Client, Cisco Secure Access.

---

## [1.3.2] — 2026-06-09

### Fixed

- **Palo Alto Prisma / GlobalProtect** remediation updated to official Microsoft coexistence guidance: In Strata Cloud Manager, add split-tunnel exclusions for `*.globalsecureaccess.microsoft.com` and GSA IPs (`150.171.19.0/24`, `13.107.232.0/24`, `151.206.0.0/16`, `6.6.0.0/16`, etc.). Disable 'Resolve All FQDNs Using DNS Servers Assigned by the Tunnel' for Private Access scenarios; enable it for Internet/M365-only scenarios. When GSA handles Internet Access, add `*.gpcloudservice.com` as GSA custom bypass. Ref: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-palo-alto-coexistence
- **Zscaler** remediation updated to official Microsoft coexistence guidance: In Zscaler Client Connector portal, create a Packet Filter-Based forwarding profile, then an app profile with GSA IPs (`150.171.15.0/24`–`6.6.0.0/16`) and FQDNs (`*.globalsecureaccess.microsoft.com`, tenant-specific client FQDNs) added to the VPN gateway bypass. When GSA handles Internet Access, add `*.prod.zpath.net` as GSA custom bypass. Ref: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-zscaler-coexistence
- **Netskope** remediation updated to official Microsoft coexistence guidance: Create 'MSFT SSE Service' and 'MSFT SSE M365' Network Location profiles in Netskope, then create a Steering Configuration with Bypass exceptions for those profiles and `*.globalsecureaccess.microsoft.com` domain. When GSA handles Internet Access, add `*.goskope.com` + Netskope IP ranges (`163.116.128.0/17`, `162.10.0.0/17`, etc.) as GSA custom bypass. Ref: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-netskope-coexistence

---

## [1.3.1] — 2026-06-09

### Fixed

- **Cisco Secure Client / AnyConnect VPN** remediation updated to official Microsoft coexistence guidance: Split-Include mode only; add GSA bypass rule for `*.vpn.sse.cisco.com` (VPNaaS) or ASA endpoint FQDN/IP; run `acsocktool.exe -slwm 10` after installing CSC v5.1.10.x+. Ref: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-cisco-vpn-coexistence
- **Cisco Secure Client – Umbrella Module** remediation updated to official Microsoft coexistence guidance: SWG must be disabled; add Umbrella IPs as GSA Internet Access bypass (`208.67.222.222`, `208.67.220.220`, `67.215.64.0/19`, `146.112.0.0/16`, etc.); add `*.globalsecureaccess.microsoft.com` and M365 FQDNs to Umbrella internal domains; run `acsocktool.exe -slwm 10` for CSC v5.1.10.x+. Ref: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-cisco-coexistence
- **Cisco Umbrella Roaming Client** remediation updated with same Umbrella coexistence guide steps: SWG disabled, Umbrella IP bypass in GSA, GSA FQDNs in Umbrella internal domains, restart Umbrella services.
- **Cisco Secure Access** remediation updated to official Microsoft coexistence guidance: add Cisco IPs and `*.zpc.sse.cisco.com` as GSA bypass; bypass `*.globalsecureaccess.microsoft.com` and GSA IP ranges in Cisco Secure Access Traffic Steering; run `acsocktool.exe -slwm 10` for CSC v5.1.10.x+. Ref: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-cisco-secure-access-coexistence

---

## [1.3.0] — 2026-06-09

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
