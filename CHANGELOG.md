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

## [Unreleased]

_(New entries go here during development)_
