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

### `vendorRemediation` schema (inside HTML template in same file)

```javascript
"VendorName": "Actionable IT admin guidance. Reference specific UI/settings. Explain split-tunnel or exclusion path first.",
```

---

## Releasing a New Version

When bumping the version (e.g. 1.1 → 1.2):

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
README.md           line ~20   | **17 vendor signatures** | Forcepoint, ...
README.md           line ~118  | 17 curated vendor patterns
docs/user-guide.html           | vendor <span> chips (one per vendor, no count text)
CHANGELOG.md                   | prose description of changes
```

The count is currently **17**. The 17 vendors are:
Forcepoint, Check Point, Skyhigh/McAfee, Zscaler, Netskope, Symantec/Broadcom, CrowdStrike, SentinelOne, Palo Alto Prisma, Cisco AnyConnect, iboss, Trellix, OpenVPN, WireGuard, Tailscale, NetLimiter, Cloudflare One.

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
