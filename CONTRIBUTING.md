# Contributing to GSA SxS Checker

Thank you for your interest in contributing! This document explains how to get started, the conventions used, and how to add new vendor signatures or improve detection.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Adding a New Vendor Signature](#adding-a-new-vendor-signature)
- [Code Style](#code-style)
- [Pull Request Workflow](#pull-request-workflow)
- [Reporting Issues](#reporting-issues)

---

## Getting Started

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Git

### Fork and Clone

```powershell
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/GSASxSChecker.git
cd GSASxSChecker
```

### Run Locally

```powershell
# Run as Administrator for full WFP output:
.\Get-GSAConflictReport.ps1
```

The script generates `GSA-Conflict-Report.html` in the current directory and opens it in your browser.

### Run with Verbose Output

```powershell
.\Get-GSAConflictReport.ps1 -Verbose
```

---

## Project Structure

```
GSASxSChecker/
├── Get-GSAConflictReport.ps1   # Main PowerShell detection script
├── GSA-Conflict-Report.html    # Sample report (anonymized demo data)
├── docs/
│   └── user-guide.html         # End-user experience guide
├── README.md
├── CONTRIBUTING.md             # This file
├── CHANGELOG.md
└── LICENSE
```

The script is intentionally **single-file** to make it easy to share, run on remote machines, and audit. Keep it that way — do not split into modules.

---

## Adding a New Vendor Signature

Vendor signatures live at the **top of `Get-GSAConflictReport.ps1`** in the `$KnownConflicts` array. Each entry is a hashtable with the following keys:

```powershell
@{
    Vendor      = "Vendor Display Name"    # e.g. "Forcepoint"
    Risk        = "High"                   # High | Medium | Low
    Keywords    = @("svcname1","drv*.sys") # wildcards supported; matched against service names and driver filenames
    Description = "One sentence explaining the conflict mechanism and its impact on GSA."
    Action      = "Vendor-specific remediation step for IT administrators."
}
```

### Example

```powershell
@{
    Vendor      = "ExampleGuard"
    Risk        = "Medium"
    Keywords    = @("exguard", "eg_wfp", "egdrv*.sys")
    Description = "ExampleGuard registers WFP callouts at ALE connect-redirect layers, competing with the GSA tunnel driver for traffic ownership."
    Action      = "Disable ExampleGuard's network inspection component or add a GSA exclusion policy via the ExampleGuard management console."
}
```

### Keyword Matching Rules

- Keywords are matched against **service name** (`Win32_SystemDriver.Name`) and **driver filename** (`Win32_SystemDriver.PathName`).
- Wildcards (`*`, `?`) are supported — the script uses PowerShell's `-like` operator.
- Add the most specific patterns first; broad patterns can cause false positives.
- All matches are **case-insensitive**.

### Verifying Your Addition

1. Add the entry to `$KnownConflicts`.
2. Run `.\Get-GSAConflictReport.ps1` on a machine where that product is installed.
3. Confirm it appears in the **Findings** tab with the correct risk level.
4. Run on a clean machine to confirm no false positives.

---

## Code Style

- **PowerShell version target**: 5.1 (avoid 7.x-only syntax).
- **No external dependencies** — the script must run with inbox PowerShell and Windows builtins only.
- **Comment important logic** — add a brief comment before each major collection block (`# --- WFP Callouts ---`).
- **HTML template**: The HTML block uses a single-quoted here-string (`@'...'@`) with `##PLACEHOLDER##` tokens replaced post-generation using `-replace`. Do **not** switch to a double-quoted here-string (`@"..."@`) — PowerShell will consume JavaScript template literal expressions (`${expr}`) inside it.
- **JSON serialization helpers**:
  - `ConvertTo-SafeJson` — use for arrays (adds `[…]` wrapper for single items).
  - `ConvertTo-SafeJsonObject` — use for the top-level `META` object (no array wrapping, must stay `{…}`).
- **Color / theming**: All colors in the HTML must use `var(--cp-*)` CSS variables — never hardcode hex values.

---

## Pull Request Workflow

1. Create a feature branch:

   ```powershell
   git checkout -b feature/add-exampleguard-signature
   ```

2. Make your changes and test locally (admin + non-admin).
3. Update [CHANGELOG.md](CHANGELOG.md) under the `[Unreleased]` section.
4. Open a pull request against `main`.
5. Fill in the PR template: describe what the vendor does, how the conflict manifests, and how you tested.

---

## Reporting Issues

Use [GitHub Issues](https://github.com/jeevanbisht/GSASxSChecker/issues).

Please include:
- Windows version (`winver`)
- GSA Client version (shown in System Info tab)
- The conflicting product name and version
- Whether the machine was run as Administrator
- The HTML report (anonymize any sensitive data first)
