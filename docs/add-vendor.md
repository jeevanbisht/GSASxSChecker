# How to Add a New Vendor

This document is the single source of truth for adding a new WFP conflict vendor to `Get-GSAConflictReport.ps1`. Follow every step in order — each one updates a different part of the generated HTML report.

---

## Checklist

- [ ] Step 1 — Add detection entry to `$KnownVendors`
- [ ] Step 2 — Add remediation guidance to `vendorRemediation`
- [ ] Step 3 — Update script `.DESCRIPTION` header
- [ ] Step 4 — Update `README.md` vendor count and table
- [ ] Step 5 — Add `CHANGELOG.md` entry
- [ ] Step 6 — Test locally
- [ ] Step 7 — Commit and push

---

## Step 1 — `$KnownVendors` (detection logic)

**File:** `Get-GSAConflictReport.ps1`  
**Location:** The `$KnownVendors = @(...)` block, around line 109.

Add a new hashtable entry **before the closing `)`**:

```powershell
@{ Name="VendorName"; Risk="High|Medium|Low"; Drivers=@("driver1","driver2"); Services=@("SvcName1","SvcName2"); Desc="One-sentence description of the WFP conflict and its user-visible symptoms." }
```

**Field reference:**

| Field | Type | Notes |
|---|---|---|
| `Name` | `string` | Exact string — must match the key used in `vendorRemediation` (Step 2) |
| `Risk` | `"High"` / `"Medium"` / `"Low"` | High = direct tunnel conflict. Medium = conditional. Low = telemetry-only. |
| `Drivers` | `string[]` | Kernel driver names to match via `Win32_SystemDriver` (`Name` or `DisplayName`, wildcard `*pattern*`). Use the actual SCM service name (e.g. `nldrv`, not `nldrv.sys`). |
| `Services` | `string[]` | Service names to match via `Get-Service` (`Name` or `DisplayName`, wildcard). Required for user-mode products that have no kernel driver. |
| `Desc` | `string` | Shown in the **Findings** tab. Focus on WFP layer impact and user-visible symptoms. Avoid competitive framing. |

**Driver vs Service detection:**
- If the product installs a **kernel driver** (registry `Type=1`), put it in `Drivers`. It will be found by `Win32_SystemDriver` (running drivers only).
- If the product is **user-mode only** (registry `Type=16/32`), it will not appear in `Win32_SystemDriver`. Put it in `Services` only.
- Products that use a **shared driver** (e.g. `wintun` used by both WireGuard and Tailscale) should still include their own service names for disambiguation.

**How to discover driver/service names on a live machine:**
```powershell
# Find running kernel drivers matching a product name
Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -match 'keyword' -or $_.PathName -match 'keyword' } | Format-Table Name, DisplayName, State, PathName

# Find services (including user-mode)
Get-Service | Where-Object { $_.Name -match 'keyword' -or $_.DisplayName -match 'keyword' } | Format-Table Name, DisplayName, Status

# Confirm driver type (1=kernel, 16/32=user-mode)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName>" | Select-Object Type, ImagePath

# Confirm driver signer
Get-AuthenticodeSignature "C:\Windows\System32\drivers\<driver>.sys" | Select-Object -Exp SignerCertificate | Select-Object Subject
```

---

## Step 2 — `vendorRemediation` (Remediation tab)

**File:** `Get-GSAConflictReport.ps1`  
**Location:** The `const vendorRemediation = { ... }` JavaScript object inside the HTML template, around line 1138.

Add a new key/value entry. **The key must exactly match the `Name` field from Step 1:**

```javascript
"VendorName": "Actionable guidance for the customer. Focus on split-tunneling configuration, exclusion rules, or which component to disable. Include specific setting names or console locations where known.",
```

**Writing good remediation text:**
- Start with what the customer should do, not what the product does wrong.
- Reference specific product UI/settings where possible (e.g. "In the Zscaler ZCC console, under Policy → Forwarding Rules...").
- For products that can coexist with configuration (split-tunnel, exclusions), explain that path first.
- For products that fundamentally cannot run alongside GSA, state that clearly but neutrally (e.g. "...on devices where GSA is the active network access client").
- Do not use competitive framing ("X blocks Y", "only one can win").

If no remediation key exists for a detected vendor, the report falls back to a generic message — so this step is important.

---

## Step 3 — Script `.DESCRIPTION` header

**File:** `Get-GSAConflictReport.ps1`  
**Location:** The `.DESCRIPTION` comment block at the top of the file (around line 11–13).

Update the vendor list sentence to include the new product name:

```powershell
#     drivers and services from known security vendors (Forcepoint, Check Point,
#     ..., YourNewVendor, and more)
```

---

## Step 4 — `README.md`

Two places need updating:

**A. Features table** — update the vendor count and add the product name:

```markdown
| **18 vendor signatures** | ..., YourNewVendor |
```

**B. Detection pipeline description** — update the count:

```markdown
3. Vendor signature matching   →  18 curated vendor patterns
```

---

## Step 5 — `CHANGELOG.md`

Add a bullet under the current `[Unreleased]` section, or create a new version block:

```markdown
- **YourNewVendor** conflict signature (Risk: High/Medium/Low) — detects `driver1`, `driver2` kernel drivers
  and `SvcName1` / `SvcName2` services. Brief sentence on why it conflicts with GSA.
```

---

## Step 6 — Test locally

Run the script without elevation first, then as Administrator if available:

```powershell
# Non-admin (baseline)
powershell -ExecutionPolicy Bypass -File .\Get-GSAConflictReport.ps1 -NoBrowser -OutputPath ".\test-report.html"

# As Administrator (full WFP callout data)
# Right-click PowerShell → Run as Administrator, then:
.\Get-GSAConflictReport.ps1 -NoBrowser -OutputPath ".\test-report-admin.html"
```

**Verify in the output:**
- The console output lists the new vendor under "conflicting product(s) detected"
- Open `test-report.html` and check each tab:
  - **Summary** tab → vendor appears in the Detected Conflicts list
  - **Findings** tab → finding card shows correct Risk badge, Desc text, and matched drivers/services
  - **Remediation** tab → vendor-specific remediation text is shown (not the generic fallback)
  - **WFP Details** tab → if admin, WFP callout/provider data is populated

**If the vendor is NOT detected on your local machine** (i.e. the product isn't installed), you can temporarily add a test driver name that exists locally to verify the rendering path, then revert before committing.

---

## Step 7 — Commit and push

```powershell
git add Get-GSAConflictReport.ps1 README.md CHANGELOG.md
git commit -m "feat: add <VendorName> to WFP conflict vendor list

- <VendorName> (Risk: <Level>): detects <drivers> kernel driver(s) and <services> service(s)
- <One line on why/how conflict occurs>
- Confirmed detected on test machine / Not testable locally (no install)
- Vendor count bumped to N in README and CHANGELOG"
git push
```

---

## Report tab mapping

For reference, here is how each data source maps to the HTML report tabs:

| Data source | Where it comes from | Tabs that show it |
|---|---|---|
| `$KnownVendors` + driver/service scan | PowerShell detection loop | Summary, Findings, Remediation |
| `netsh wfp show state` | Admin-only WFP XML dump | WFP Details |
| `Win32_SystemDriver` (non-MS) | All running kernel drivers | Kernel Drivers |
| WMI / registry / dsregcmd | System/identity collection | System Info |
| `vendorRemediation` JS object | Embedded in HTML template | Remediation |

---

## Risk level guidance

| Risk | When to use |
|---|---|
| **High** | Product registers WFP callouts at `ALE_CONNECT_REDIRECT` or `ALE_AUTH_CONNECT` layers and is known to cause tunnel failures or traffic drops when GSA is active. |
| **Medium** | Product uses WFP but symptoms are conditional (e.g. depends on policy config, split-tunnel settings, or overlapping routes). Coexistence is possible with configuration. |
| **Low** | Product uses WFP only for passive telemetry/logging. Generally coexists but may cause intermittent issues in edge cases. |
