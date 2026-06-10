# Maintenance Instructions for AI Agents

This file is the **single source of truth for making changes to this repository**.
Read it before editing any file. It maps every type of change to every file that must be updated.

---

## Repository Layout

```
Get-GSAConflictReport.ps1   # ONLY script — intentionally single-file; do not split
GSA-Conflict-Report.html    # Sample/demo report; regenerate with -NoBrowser after script changes
AGENTS.md                   # This file
README.md
CONTRIBUTING.md
CHANGELOG.md
LICENSE
docs/
  add-vendor.md             # Canonical step-by-step guide for adding vendors (detailed)
  user-guide.html           # End-user guide (standalone HTML, no build step)
```

---

## Adding a New Vendor

All 6 items below **must** be done together. Never commit a vendor addition that touches fewer.

| # | File | What to change |
|---|---|---|
| 1 | `Get-GSAConflictReport.ps1` | Add hashtable to `$KnownVendors` array (~line 109) |
| 2 | `Get-GSAConflictReport.ps1` | Add key/value to `vendorRemediation` JS object in HTML template (~line 1138) |
| 3 | `Get-GSAConflictReport.ps1` | Update `.DESCRIPTION` header vendor name list (~line 8–13) |
| 4 | `README.md` | Bump vendor count (features table + detection pipeline line) |
| 5 | `CHANGELOG.md` | Add bullet under `[Unreleased]` or new version block |
| 6 | `docs/user-guide.html` | Add `<span>` chip to "Detected Vendor Products" section |

**Detailed field reference and discovery commands:** [`docs/add-vendor.md`](docs/add-vendor.md)

### `$KnownVendors` schema (file: `Get-GSAConflictReport.ps1`)

```powershell
@{ Name="VendorName"; Risk="High|Medium|Low"; Drivers=@("driver1","driver2"); Services=@("SvcName1","SvcName2"); Desc="One-sentence WFP conflict description." }
```

| Field | Rules |
|---|---|
| `Name` | Must exactly match the key used in `vendorRemediation` |
| `Risk` | `"High"` = direct tunnel conflict · `"Medium"` = conditional · `"Low"` = telemetry only |
| `Drivers` | SCM service names (no `.sys`), matched via `Win32_SystemDriver`. Use `"*pattern*"` wildcards. |
| `Services` | Matched via `Get-Service` `Name`/`DisplayName`. Required when product has no kernel driver. |
| `Desc` | Shown in Findings tab. Describe WFP layer impact. Avoid competitive framing. |

### ⚠️ Pattern Safety Rules — read before adding any driver or service name

All driver and service patterns are matched as **case-insensitive substrings** (`*pattern*`). A 3-character pattern like `"ose"` will match **any** driver/service whose name contains those letters — including unrelated Windows components.

**Hard rules:**

| Rule | Example violation | Correct fix |
|---|---|---|
| **Minimum 5 characters** for any pattern | `"ose"`, `"eaa"`, `"amp"`, `"via"`, `"epp"`, `"dsp"` | Use the full service name: `"osevpn"`, `"akamaiaccess"` |
| **No generic English words** | `"shield"`, `"orbital"`, `"mobility"`, `"keeper"` alone | Prefix with vendor brand: `"EricomShield"`, `"CiscoOrbital"` |
| **No Windows built-in abbreviations** | `"sfc"` (Windows SFC), `"cpd"` (AMD CPD service), `"warp"` (Windows Warp JIT Service) | Remove entirely; use longer product-specific strings |
| **No shared infrastructure names alone** | `"wintun"` alone (used by WireGuard, Tailscale, NetBird, Headscale, Perimeter 81…) | Always pair with a product-specific service name |
| **Prefer exact brand names** | `"amon"`, `"masvc"` | Use `"CheckPoint"`, `"McAfee"` or the full service display name |

**Known false positives caught and fixed (do not re-add these patterns):**

| Pattern | Vendor it was in | Matched incorrectly |
|---|---|---|
| `"WARP"` | Cloudflare One | Windows Warp JIT Service (WinAppSDK MSIX JIT) |
| `"ose"` | Open Systems SASE | AMD audio kernel drivers |
| `"cpd"` | Check Point | AMD Crash Prevention Device service (`AMDCPDService`) |
| `"amon"` | Check Point | Generic monitoring agent names |
| `"amp"` | Cisco Secure Endpoint | AMD amplifier/audio components |
| `"via"` | Aruba VIA | VIA Technologies chipset drivers (`viaXxx.sys`) |
| `"epp"` | CoSoSys Endpoint Protector | Other EPP/EDR products |
| `"dsp"` | ManageEngine DataSecurity Plus | Generic DSP/audio components |
| `"shield"` | Ericom Shield | Other security products using "Shield" branding |
| `"eaa"` | Akamai EAA | Generic EAA acronym collisions |
| `"sfc"` | Cisco Secure Endpoint | Windows System File Checker components |

**Quick self-check before committing:**
```powershell
# Run this on a clean Windows machine before finalising any pattern.
# If results include non-vendor services, the pattern is too broad.
Get-Service | Where-Object { $_.Name -like "*yourpattern*" -or $_.DisplayName -like "*yourpattern*" } | Format-Table Name, DisplayName, Status
Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "*yourpattern*" -or $_.DisplayName -like "*yourpattern*" } | Format-Table Name, DisplayName, State
```

### `vendorRemediation` schema (inside HTML template in same file)

```javascript
"VendorName": "Actionable IT admin guidance. Reference specific UI/settings. Explain split-tunnel or exclusion path first.",
```

---

## Releasing a New Version

### Semantic versioning rules

Bump the version on **every commit that changes the script**:

| Change type | Version bump | Examples |
|---|---|---|
| New vendor signature | **Minor** (1.X.0) | Adding any `$KnownVendors` entry |
| New detection capability / new report tab or section | **Minor** (1.X.0) | New data source, new HTML tab |
| Bug fix / false-positive fix / driver list correction | **Patch** (1.1.X) | Fixing a wrong driver name, remediation text fix |
| Documentation-only (no `.ps1` change) | **No bump** | README, AGENTS.md, CHANGELOG edits only |
| Breaking change (parameter removed/renamed, report schema change) | **Major** (X.0.0) | Removing a parameter, changing placeholder tokens |

### Files to update when bumping version

| File | Change |
|---|---|
| `Get-GSAConflictReport.ps1` | `$script:Version = 'X.Y.Z'` (line after `param()` block) |
| `Get-GSAConflictReport.ps1` | `.NOTES` → `Version : X.Y.Z` |
| `CHANGELOG.md` | Rename `[Unreleased]` block to `[X.Y.Z] — YYYY-MM-DD`; add new empty `[Unreleased]` at top |
| `README.md` | No version number tracked here |
| `docs/user-guide.html` | Update `<span class="badge">vX.Y</span>` in the header (line ~285) |

---

## Editing the HTML Report Template

The HTML is a **single-quoted PowerShell here-string** (`@'...'@`) inside `Get-GSAConflictReport.ps1`.

- **Do NOT** convert it to a double-quoted here-string (`@"..."@`) — PowerShell will expand `${...}` JavaScript template literals inside it.
- Data is injected via `##PLACEHOLDER##` tokens replaced with `-replace` after the here-string is closed.
- All colors must use `var(--cp-*)` CSS variables — never hardcode hex values.
- `ConvertTo-SafeJson` — use for arrays (adds `[…]` wrapper for single-element arrays).
- `ConvertTo-SafeJsonObject` — use for the top-level `META` object only.

---

## PowerShell Code Rules

- **Target PowerShell 5.1** — avoid 7.x-only syntax (`??=`, ternary `? :`, `ForEach-Object -Parallel`, etc.).
- **No external modules** — inbox PowerShell and Windows builtins only (`WMI`, `Get-Service`, `netsh`, `dsregcmd`, registry).
- **No `Get-WmiObject`** — use `Get-CimInstance` (available in PS 5.1; returns native .NET `DateTime` objects).
- Use `Get-CimInstance Win32_SystemDriver` for driver enumeration, not `Win32_SystemDriver` via `Get-WmiObject`.

---

## Counts to Keep in Sync

Whenever the vendor count changes, update **all three** of these:

```
README.md           line ~20   | **49 vendor signatures** | Forcepoint, ...
README.md           line ~118  | 49 curated vendor patterns
docs/user-guide.html           | vendor <span> chips (one per vendor, no count text)
CHANGELOG.md                   | prose description of changes
```

The count is currently **49**. The 49 vendors are:
Forcepoint, Check Point, Skyhigh/McAfee, Zscaler, Netskope, Cloudflare One, iboss, Palo Alto Prisma/GlobalProtect, Cisco Secure Client/AnyConnect, Cisco Umbrella Module, Cisco Umbrella Roaming Client, Cisco Secure Endpoint, Cisco Secure Access, Cisco AnyConnect NVM, Citrix Secure Access/NetScaler Gateway, Fortinet FortiClient, Ivanti Secure Access/Pulse Secure, F5 BIG-IP Edge Client, SonicWall NetExtender, Sophos Connect/ZTNA, Absolute Secure Access/NetMotion, Appgate SDP, Akamai EAA, Twingate, Trellix, Symantec/Broadcom, CrowdStrike, SentinelOne, OpenVPN, WireGuard, Tailscale, NetLimiter, Perimeter 81, NordLayer, Keeper Connection Manager, Open Systems SASE, Barracuda VPN, WatchGuard Mobile VPN, Array Networks VPN, Aruba VIA, Digital Guardian, Proofpoint Endpoint DLP, CoSoSys Endpoint Protector, ManageEngine DataSecurity Plus, Menlo Security, Ericom Shield, ZeroTier, NetBird, Headscale.

---

## Commit Message Convention

```
feat: add <VendorName> to WFP conflict vendor list

- <VendorName> (Risk: <Level>): detects <drivers> kernel driver(s) and <services> service(s)
- <One line on conflict mechanism>
- Confirmed detected on test machine / Not testable locally (no install)
- Vendor count bumped to N in README and docs
```

For documentation-only changes: `docs: ...`
For bug fixes: `fix: ...`
For style/formatting: `style: ...`
