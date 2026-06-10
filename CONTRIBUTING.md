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
├── Sample-GSA-Conflict-Report.html    # Sample report (anonymized demo data)
├── docs/
│   ├── user-guide.html         # End-user experience guide
│   └── add-vendor.md           # Step-by-step vendor onboarding guide (canonical reference)
├── README.md
├── CONTRIBUTING.md             # This file
├── CHANGELOG.md
└── LICENSE
```

The script is intentionally **single-file** to make it easy to share, run on remote machines, and audit. Keep it that way — do not split into modules.

---

## Adding a New Vendor Signature

> **Full step-by-step guide:** [`docs/add-vendor.md`](docs/add-vendor.md) — follow that document for detailed instructions and field reference. This section is a quick summary.

Adding a vendor touches **two places** in `Get-GSAConflictReport.ps1` plus several documentation files:

### Step 1 — `$KnownVendors` (detection logic)

Array at the top of the script (~line 109). Add a new hashtable **before the closing `)`**:

```powershell
@{ Name="VendorName"; Risk="High"; Drivers=@("driver1","driver2"); Services=@("SvcName1","SvcName2"); Desc="One-sentence WFP conflict description." }
```

| Field | Notes |
|---|---|
| `Name` | Display name — must exactly match the key in `vendorRemediation` (Step 2) |
| `Risk` | `"High"` / `"Medium"` / `"Low"` |
| `Drivers` | Kernel driver SCM names (matched via `Win32_SystemDriver`). Use `"*pattern*"` wildcards. |
| `Services` | User-mode service names (matched via `Get-Service`). Required when no kernel driver. |
| `Desc` | Shown in the Findings tab. WFP layer impact and user-visible symptoms. |

### Step 2 — `vendorRemediation` (Remediation tab)

JavaScript object inside the HTML template (~line 1138). Add a key matching `Name` from Step 1:

```javascript
"VendorName": "Actionable remediation guidance for the customer.",
```

### Step 3 — Update documentation

| File | What to update |
|---|---|
| `Get-GSAConflictReport.ps1` | `.DESCRIPTION` header — add vendor to the name list |
| `README.md` | Vendor count in features table + detection pipeline description |
| `CHANGELOG.md` | Entry under `[Unreleased]` or new version block |
| `docs/user-guide.html` | Vendor chip in the "Detected Vendor Products" section + version badge if releasing |

### Keyword matching rules

- `Drivers` entries are matched against `Win32_SystemDriver.Name` (SCM service name, not filename — no `.sys` extension).
- `Services` entries are matched against `Get-Service` `Name` and `DisplayName`.
- Wildcards (`*`) use PowerShell `-like`. Keep patterns specific to avoid false positives.
- All matches are **case-insensitive**.

### Verifying Your Addition

1. Add the entry to `$KnownVendors` and the remediation key to `vendorRemediation`.
2. Run `.\Get-GSAConflictReport.ps1` on a machine where that product is installed.
3. Confirm it appears in the **Findings** tab with the correct risk level and remediation text.
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
