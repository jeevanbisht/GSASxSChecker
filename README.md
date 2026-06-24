<div align="center">

# GSA SxS Checker

### Find what conflicts with the Microsoft Global Secure Access client — in one command.

A single PowerShell script that scans a Windows machine for network-security products whose
**Windows Filtering Platform (WFP)** drivers can clash with the **Global Secure Access (GSA)**
client, and produces a polished, self-contained HTML report you can read, share, or attach to a
support case.

[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://docs.microsoft.com/powershell/)
[![Platform: Windows 10/11](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%2F%20Server-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![58 vendor signatures](https://img.shields.io/badge/Vendor%20signatures-58-2EAD33)](#-whats-detected)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Issues](https://img.shields.io/github/issues/jeevanbisht/GSASxSChecker)](https://github.com/jeevanbisht/GSASxSChecker/issues)

[Quick Start](#-quick-start) · [Sample Report](#-sample-report) · [How It Works](#-how-detection-works) · [Privacy](#-privacy--data-handling) · [FAQ](#-faq--troubleshooting)

</div>

---

## The problem this solves

The Global Secure Access client tunnels traffic by registering a **kernel-mode WFP callout
driver** (`GlobalSecureAccessDriver`) at the Windows Filtering Platform's connect-redirect layers.
Many other products — enterprise SASE/VPN agents, endpoint DLP, EDR, and even consumer VPNs —
register callouts at those **same** layers.

When two products contend for the same network decision, the symptoms are frustrating and hard to
diagnose:

- 🔌 GSA tunnels fail to establish or silently drop
- 🌐 Traffic is misrouted, or specific apps/sites stop working only when GSA is on
- 💥 Connectivity is intermittent, or the machine becomes unstable

**GSA SxS Checker** answers the first question every troubleshooting session asks — *"Is something
else on this machine fighting GSA for the network?"* — objectively, in seconds, with evidence you
can hand to your IT team or Microsoft support.

> [!NOTE]
> This is a **discovery and recommendation** tool. It inspects the **local machine only** and does
> not change any system state. If you have already applied a remediation, some warnings may still
> appear until the conflicting product is fully removed or reconfigured. Always confirm against the
> [official Microsoft Global Secure Access documentation](https://learn.microsoft.com/entra/global-secure-access/)
> for the latest guidance.

---

## Table of Contents

- [Who it's for](#who-its-for)
- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📸 Sample Report](#-sample-report)
- [📑 Understanding the Report](#-understanding-the-report)
- [🎯 Confidence Model](#-confidence-model-confirmed-vs-low-confidence)
- [🔧 Parameters](#-parameters)
- [🔍 How Detection Works](#-how-detection-works)
- [📋 Requirements](#-requirements)
- [🔒 Privacy & Data Handling](#-privacy--data-handling)
- [🧩 What's Detected](#-whats-detected)
- [❓ FAQ & Troubleshooting](#-faq--troubleshooting)
- [🤝 Contributing](#-contributing)
- [📜 Changelog · 📄 License](#-changelog)

---

## Who it's for

| You are… | Use it to… |
|---|---|
| **An IT admin / help-desk engineer** | Triage a "GSA isn't connecting" ticket without deep packet captures. |
| **A network / security architect** | Inventory coexisting WFP products before a GSA rollout. |
| **A Microsoft support engineer** | Get a consistent, evidence-grade machine snapshot from the customer. |
| **An end user** | Run one command and send the resulting HTML file to your IT team. |

---

## ✨ Features

| Capability | What you get |
|---|---|
| **One command, zero install** | A single `.ps1` script using only inbox Windows tools — no modules, no internet, no agent. |
| **58 vendor signatures** | Curated detection for SASE, VPN, EDR, and DLP products known to register WFP callouts (see [What's Detected](#-whats-detected)). |
| **WFP callout enumeration** | Live Windows Filtering Platform engine dump via `netsh wfp show state` (Administrator). |
| **Kernel driver signer detection** | Every running non-Microsoft kernel driver, with publisher and signer. |
| **GSA client status** | Version, services, and per-channel tunnel health (M365 / Internet / Private / Entra). |
| **Entra ID join detection** | Cloud, Hybrid, On-prem, or Workgroup — via `dsregcmd`. |
| **Risk scoring** | A clear None / Low / Medium / High banner with actionable, vendor-specific remediation. |
| **Confidence-aware findings** | Distinguishes **confirmed** conflicts (service matched) from **low-confidence** driver-only matches. |
| **Self-contained HTML report** | One portable file — no server, works offline, safe to email or attach to a case. |
| **Dark / light mode** | Auto-detects OS preference, with a toggle in the report header. |

---

## 🚀 Quick Start

### 1 — Get the script

```powershell
git clone https://github.com/jeevanbisht/GSASxSChecker.git
cd GSASxSChecker
```

…or download just the one file:

```powershell
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/jeevanbisht/GSASxSChecker/master/Get-GSAConflictReport.ps1" `
  -OutFile "Get-GSAConflictReport.ps1"
```

### 2 — Run it (as Administrator for full results)

Right-click **PowerShell** → **Run as Administrator**, then:

```powershell
.\Get-GSAConflictReport.ps1
```

The report is generated and opens automatically in your default browser.

> If script execution is blocked, run it for the current session only:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
> .\Get-GSAConflictReport.ps1
> ```

### 3 — Read & share

Open `GSA-Conflict-Report.html`, review the risk banner, and send the file to your IT team or
attach it to a support ticket. Everything needed to read it is inside that one file.

---

## 📸 Sample Report

A fully rendered example (with anonymized machine data) is included:
[`Sample-GSA-Conflict-Report.html`](Sample-GSA-Conflict-Report.html).

![GSA SxS Checker sample report](Sample.png)

---

## 📑 Understanding the Report

The report is organized into tabs so both engineers and non-technical readers can find what they
need:

| Tab | What you'll see |
|---|---|
| **Summary** | Overall risk banner, machine snapshot, and a quick count of confirmed conflicts. |
| **Findings** | Per-vendor risk level, the drivers/services that matched, and a plain-language conflict description. |
| **WFP Details** | Raw WFP callout drivers and providers from the live engine dump (Administrator only). |
| **Kernel Drivers** | Every running non-Microsoft kernel driver with its signer/publisher. |
| **System Info** | Identity, OS, hardware, GSA client status, Entra join type, and network adapters. |
| **Remediation** | Vendor-specific next steps and copy-paste diagnostic commands. |

---

## 🎯 Confidence Model (confirmed vs. low-confidence)

Not every match is equally certain, so the tool grades findings:

- **Confirmed (Match = Yes)** — a vendor **service name** actually matched on this machine. These
  are high-confidence and drive the default risk banner and conflict counts.
- **Low-confidence (Match = No)** — only a **driver name** matched. Because several products can
  ship the *same* underlying driver (e.g. `wintun`, common to many WireGuard-based VPNs), a
  driver-only match may list multiple possible product names even though only one is installed.

By default the report shows **confirmed conflicts only**, with a note telling you how many
low-confidence matches were hidden. Use **`-ShowAll`** to include them, then use the **Findings**
tab to verify which specific services and binaries are actually present.

---

## 🔧 Parameters

```powershell
Get-Help .\Get-GSAConflictReport.ps1 -Full
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | `string` | `.\GSA-Conflict-Report.html` | Path for the generated report. |
| `-NoBrowser` | `switch` | `$false` | Don't auto-open the report (useful for automation). |
| `-ShowAll` | `switch` | `$false` | Include low-confidence, driver-only matches in the Detected Conflicts and Findings views. |

### Examples

```powershell
# Standard run — generate and open the report
.\Get-GSAConflictReport.ps1

# Custom, machine-stamped output path
.\Get-GSAConflictReport.ps1 -OutputPath "C:\Reports\GSA-$(hostname)-$(Get-Date -f yyyyMMdd).html"

# Silent run for scripting / fleet collection (no browser pop-up)
.\Get-GSAConflictReport.ps1 -NoBrowser

# Include low-confidence driver-only matches for deeper investigation
.\Get-GSAConflictReport.ps1 -ShowAll

# Run on a remote machine and collect the result
Invoke-Command -ComputerName TARGET-PC -FilePath .\Get-GSAConflictReport.ps1
```

---

## 🔍 How Detection Works

The GSA client registers a **kernel-mode WFP callout driver** that operates at the Windows
Filtering Platform layers `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`. When a competing product also
registers at those layers, WFP's filter weight/priority system decides who handles each network
decision — which is where conflicts arise.

**Detection pipeline:**

```
1. Get-CimInstance Win32_SystemDriver   →  all SCM-registered kernel-mode drivers
2. netsh wfp show state                 →  live WFP callout + provider enumeration (admin)
3. Vendor signature matching            →  58 curated vendor patterns (driver + service)
4. GSA registry / services              →  client version, channel status, service health
5. dsregcmd /status                     →  Entra ID / Hybrid / On-prem join detection
```

> **Scope:** Detects WFP callout drivers registered via the Windows Filtering Platform API and
> vendor services registered with the Service Control Manager. It does **not** detect drivers
> loaded without SCM registration, or non-WFP hooks (NDIS filters, LSPs).

---

## 📋 Requirements

- **OS:** Windows 10 / 11 or Windows Server 2016+
- **PowerShell:** 5.1 or later (built into Windows — no install required)
- **Elevation:** Run as **Administrator** for full WFP callout enumeration. Without elevation the
  report still runs, but the WFP Callouts/Providers sections will be empty.
- **Dependencies:** None. The script uses only inbox Windows tooling (WMI/CIM, `Get-Service`,
  `netsh`, `dsregcmd`, registry).

---

## 🔒 Privacy & Data Handling

Built to be safe to run on production and customer machines:

- **Runs entirely locally.** No network calls, no telemetry, no phone-home — the script needs no
  internet access to work.
- **Read-only.** It inspects drivers, services, registry, and WFP state; it never modifies system
  configuration.
- **You control the output.** The single HTML report is written where you choose and contains only
  the machine inventory shown in the tabs. Review it before sharing externally.
- **Portable & inspectable.** It's one readable PowerShell file and one HTML file — both can be
  audited before use in restricted environments.

---

## 🧩 What's Detected

**58 vendor signatures** spanning SASE/SSE, VPN, EDR, and DLP products that register WFP callouts
or network drivers, including:

> Forcepoint · Check Point · Skyhigh/McAfee · Zscaler · Netskope · Cloudflare One · iboss · Palo
> Alto Prisma & GlobalProtect · Cisco (Secure Client/AnyConnect, Umbrella, Secure Endpoint, Secure
> Access, AnyConnect NVM) · Citrix Secure Access · Fortinet FortiClient · Ivanti/Pulse Secure · F5
> BIG-IP Edge · SonicWall NetExtender · Sophos Connect/ZTNA · Absolute/NetMotion · Appgate SDP ·
> Akamai EAA · Twingate · Trellix · Symantec/Broadcom · CrowdStrike · SentinelOne · OpenVPN ·
> WireGuard · Tailscale · NetLimiter · Perimeter 81 · NordLayer · Keeper Connection Manager · Open
> Systems SASE · Barracuda VPN · WatchGuard Mobile VPN · Array Networks VPN · Aruba VIA · Digital
> Guardian · Proofpoint Endpoint DLP · CoSoSys Endpoint Protector · ManageEngine DataSecurity Plus ·
> Menlo Security · Ericom Shield · ZeroTier · NetBird · Headscale · Cato Networks · VMware Workspace
> ONE Tunnel · BeyondTrust · NordVPN · ExpressVPN · Surfshark · Proton VPN · Mullvad VPN · Cita VPN
> · and more.

Missing a product? [Open an issue](https://github.com/jeevanbisht/GSASxSChecker/issues) or add a
signature — see [Contributing](#-contributing).

---

## ❓ FAQ & Troubleshooting

**The WFP Details tab is empty.**
You ran without elevation. Re-run PowerShell **as Administrator** for the full WFP callout dump.

**A vendor is listed that I don't think is installed.**
You're likely seeing a **low-confidence, driver-only** match (shared driver such as `wintun`).
Check the **Findings** tab to see whether a matching *service* is actually present.

**I already fixed the conflict but still see warnings.**
The tool reports current machine state. Warnings clear once the conflicting product is fully
removed or reconfigured (e.g. split-tunnel/exclusion applied and services stopped).

**Script won't run — "running scripts is disabled".**
Use a per-session bypass:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

**Does it work over PowerShell 7?**
The script targets Windows PowerShell 5.1 (inbox). It is designed for the version shipped with
Windows; run it from a standard elevated Windows PowerShell prompt for best results.

---

## 🤝 Contributing

Contributions are welcome — especially new vendor signatures. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) and the maintainer guide [`docs/add-vendor.md`](docs/add-vendor.md)
before submitting, and follow the pattern-safety rules to avoid false positives.

---

## 📜 Changelog

See [CHANGELOG.md](CHANGELOG.md). Current version: **1.7.0**.

## 📖 End-User Guide

A standalone, non-technical walkthrough is available at [`docs/user-guide.html`](docs/user-guide.html).

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## 🔗 Related Resources

- [GSA client troubleshooting & advanced diagnostics](https://learn.microsoft.com/entra/global-secure-access/troubleshoot-global-secure-access-client-advanced-diagnostics)
- [Windows Filtering Platform architecture](https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page)
- [Global Secure Access documentation](https://learn.microsoft.com/entra/global-secure-access/)
