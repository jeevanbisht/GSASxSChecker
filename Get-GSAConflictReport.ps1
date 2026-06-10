<#
.SYNOPSIS
    Detects Windows Filtering Platform (WFP) driver conflicts with the Microsoft
    Global Secure Access (GSA) client and generates a self-contained HTML report.

.DESCRIPTION
    Get-GSAConflictReport scans the local machine for kernel-mode WFP callout
    drivers and services from known security vendors (Forcepoint, Check Point,
    Skyhigh, Zscaler, Netskope, Palo Alto, CrowdStrike, SentinelOne, Symantec,
    Cisco AnyConnect, iboss, Trellix, OpenVPN, WireGuard, Cloudflare One, and more)
    that are known to conflict with the Microsoft Global Secure Access (GSA) client.

    The GSA client uses a WFP callout driver (GlobalSecureAccessDriver) to intercept
    and tunnel network traffic. When competing products register callouts at the same
    ALE (Application Layer Enforcement) network layers, traffic can be silently
    dropped — sometimes a leading cause of tunnels failing to establish, traffic being silently dropped, or the machine becoming unstable.

    The generated HTML report includes:
      - Risk banner (None / Low / Medium / High) with conflict count
      - Summary tab    : quick machine snapshot and detected conflicts
      - Findings tab   : per-vendor risk, matched drivers/services, descriptions
      - WFP Details tab: raw WFP callout drivers and providers (admin-only)
      - Kernel Drivers : all running non-Microsoft kernel drivers with signer info
      - System Info    : identity, OS, hardware, runtime, GSA client status,
                         Entra ID join type, and network adapters
      - Remediation    : vendor-specific actions and diagnostic commands

    Detection methods used:
      1. Win32_SystemDriver WMI  - all running SCM-registered kernel drivers
      2. netsh wfp show state    - live WFP engine dump (requires Administrator)
      3. Service name matching   - known vendor service name patterns
      4. Registry / file version - GSA client install detection

.PARAMETER OutputPath
    Path for the generated HTML report file.
    Defaults to .\GSA-Conflict-Report.html in the current directory.

.PARAMETER NoBrowser
    Suppress automatically opening the report in the default browser after generation.

.EXAMPLE
    # Basic usage — generates report in current directory
    .\Get-GSAConflictReport.ps1

.EXAMPLE
    # Run as Administrator for full WFP callout enumeration
    # Right-click PowerShell → Run as Administrator, then:
    .\Get-GSAConflictReport.ps1

.EXAMPLE
    # Save report to a specific path
    .\Get-GSAConflictReport.ps1 -OutputPath "C:\Reports\MyMachine-GSA-$(Get-Date -f yyyyMMdd).html"

.EXAMPLE
    # Generate silently without opening browser (useful in automated collection)
    .\Get-GSAConflictReport.ps1 -NoBrowser

.EXAMPLE
    # Collect from a remote machine (run locally on target, copy report back)
    Invoke-Command -ComputerName TARGET-PC -FilePath .\Get-GSAConflictReport.ps1

.INPUTS
    None. Does not accept pipeline input.

.OUTPUTS
    System.String
    Path to the generated HTML file is written to the host.

.NOTES
    Version      : 1.1.0
    Author       : Jeevan Bisht
    Project      : https://github.com/jeevanbisht/GSASxSChecker
    License      : MIT

    REQUIREMENTS:
      - Windows 10 / 11 or Windows Server 2016+
      - PowerShell 5.1 or later
      - Run as Administrator for full WFP callout data (netsh wfp show state)
        Without elevation the report still runs but WFP Callouts/Providers tabs
        will be empty and the admin warning banner will be shown.

    DETECTION SCOPE:
      Detects kernel-mode WFP callout drivers registered via the Windows Filtering
      Platform API. Does NOT detect:
        - Drivers loaded outside SCM (NtLoadDriver) without service registration
        - WFP callouts registered and already deregistered at scan time
        - Legacy NDIS filter drivers or LSP-based proxies (non-WFP)

    PRIVACY:
      The report contains machine name, username, domain, IP/MAC addresses,
      and OS build information. Treat accordingly before sharing externally.
      Use the -OutputPath parameter to control where reports are saved.

.LINK
    https://github.com/jeevanbisht/GSASxSChecker

.LINK
    https://learn.microsoft.com/en-us/entra/global-secure-access/troubleshoot-global-secure-access-client-advanced-diagnostics
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\GSA-Conflict-Report.html",

    [switch]$NoBrowser
)

# ─── Known conflicting vendors ───────────────────────────────────────────────
$KnownVendors = @(
    @{ Name="Forcepoint";      Risk="High";   Drivers=@("fpwfp","fpdodriver","fpepflt","fp_wfp");           Services=@("fpcsvc","FPWFPDriver","ForcePoint");       Desc="Forcepoint Web Security / DLP uses WFP callouts at the same ALE layers as GSA, causing packet redirect conflicts." }
    @{ Name="Check Point";     Risk="High";   Drivers=@("vsdatant","cpfw","cptlsp","cpepflt");              Services=@("CheckPoint","cpd","amon","CPDA");           Desc="Check Point Endpoint Security registers persistent WFP providers that conflict with GSA tunnel callouts." }
    @{ Name="Skyhigh/McAfee";  Risk="High";   Drivers=@("mfewfpk","mfefirek","mfehidk","cfwids");          Services=@("McAfee","Skyhigh","mfevtp","masvc");        Desc="McAfee/Trellix/Skyhigh CASB & DLP hooks at ALE_CONNECT layer directly conflict with GSA traffic steering." }
    @{ Name="Zscaler";         Risk="High";   Drivers=@("zscaler","zsa","ZSADriver");                       Services=@("ZSAService","ZscalerService","ZSTunnel");   Desc="Zscaler Client Connector and GSA both attempt to own the network redirect layer - only one can win." }
    @{ Name="Netskope";        Risk="High";   Drivers=@("nssdrv","NetskopeFilter","nswfp");                 Services=@("stAgentSvc","NetskopeService");             Desc="Netskope CASB client uses a WFP callout driver that intercepts the same traffic flows as GSA." }
    @{ Name="Symantec/Broadcom";Risk="Medium";Drivers=@("symnets","srtspx","SymEvent");              Services=@("SepMasterService","SymNetDrv");             Desc="Symantec Endpoint Protection network driver may conflict depending on policy configuration." }
    @{ Name="CrowdStrike";     Risk="Low";    Drivers=@("csagent","CrowdStrike");                          Services=@("CSFalconService","CrowdStrike");            Desc="CrowdStrike Falcon sensor uses WFP for network telemetry - generally coexists but monitor for issues." }
    @{ Name="SentinelOne";     Risk="Low";    Drivers=@("sentinelmonitor","SentinelAgent","s1filter");     Services=@("SentinelAgent","SentinelOne");              Desc="SentinelOne agent uses WFP for detection - usually low risk but can cause intermittent drops." }
    @{ Name="Palo Alto Prisma";Risk="High";   Drivers=@("pangpd","PanWFP","PanGPA");                       Services=@("PanGPS","PanGPA","PrismaAccess");           Desc="Palo Alto GlobalProtect VPN and Prisma Access both compete with GSA for network layer ownership." }
    @{ Name="Cisco AnyConnect";Risk="Medium"; Drivers=@("acvpnwfp","acsock","vpnva");                      Services=@("vpnagent","csc_svr","CiscoAnyConnect");     Desc="Cisco AnyConnect VPN uses WFP callouts that can interfere with GSA tunnel establishment." }
    @{ Name="iboss";           Risk="Medium"; Drivers=@("iboss","ibossdrv");                               Services=@("ibossService","ibossAgent");                Desc="iboss cloud connector uses network filtering that may overlap with GSA traffic interception." }
    @{ Name="Trellix";         Risk="High";   Drivers=@("mfewfpk","xagt","HipShieldK");                   Services=@("xagt","Trellix","McAfeeDLPAgentService");   Desc="Trellix (McAfee Enterprise) endpoint agent - same WFP conflict as McAfee consumer products." }
    @{ Name="OpenVPN";         Risk="Medium"; Drivers=@("ovpn-dco","tap_ovpnconnect","tapwindows","ovpnco"); Services=@("OpenVPNService","OpenVPN Connect","ovpnhelper"); Desc="OpenVPN tunnel driver (TAP/DCO) uses WFP and may conflict with GSA traffic steering at the redirect layer." }
    @{ Name="WireGuard";       Risk="Medium"; Drivers=@("wintun","WireGuard","wireguard"); Services=@("WireGuardTunnel","WireGuardManager"); Desc="WireGuard Wintun kernel driver registers WFP callouts for tunnel traffic that can conflict with GSA network interception." }
    @{ Name="Cloudflare One";  Risk="High";   Drivers=@("cfwfpco","cfwfp","cloudflare"); Services=@("CloudflareWARP","WARP","warp-svc"); Desc="Cloudflare One Client (WARP) is a competing ZTNA/SASE agent that intercepts and tunnels network traffic at the same WFP layers as GSA, causing direct conflicts with traffic steering and tunnel establishment." }
)

# ─── Collect system data ──────────────────────────────────────────────────────
$IsAdmin       = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ReportTime    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ReportTimeUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC"

# Identity
$MachineName       = $env:COMPUTERNAME
$User              = $env:USERNAME
$UserDomain        = $env:USERDOMAIN
$UserFull          = "$UserDomain\$User"

# Entra ID / Hybrid / Domain join status via dsregcmd
$JoinType      = "Not joined"
$EntraTenantName = ""
$EntraTenantId   = ""
$EntraDeviceId   = ""
$EntraPrtStatus  = ""
try {
    $dsreg = dsregcmd /status 2>&1
    $parse = { param($key) ($dsreg | Select-String "^\s*$key\s*:\s*(.+)$" | Select-Object -First 1).Matches.Groups[1].Value.Trim() }
    $azJoined  = & $parse "AzureAdJoined"
    $domJoined = & $parse "DomainJoined"
    $wpJoined  = & $parse "WorkplaceJoined"
    $EntraTenantName = & $parse "TenantName"
    $EntraTenantId   = & $parse "TenantId"
    $EntraPrtStatus  = & $parse "AzureAdPrt"
    $JoinType = if     ($azJoined -eq "YES" -and $domJoined -eq "YES") { "Hybrid Joined (Entra ID + AD)" }
                elseif ($azJoined -eq "YES")                            { "Entra ID Joined (Cloud-only)" }
                elseif ($domJoined -eq "YES")                           { "Domain Joined (On-prem only)" }
                elseif ($wpJoined -eq "YES")                            { "Workplace Registered" }
                else                                                    { "Not joined / Workgroup" }
} catch { $JoinType = "Unable to determine" }

# OS
$OSInfo            = Get-CimInstance Win32_OperatingSystem
$OSCaption         = $OSInfo.Caption
$OSVersion         = $OSInfo.Version
$OSBuild           = $OSInfo.BuildNumber
$OSInstallDate     = try { $OSInfo.InstallDate.ToString("yyyy-MM-dd") }   catch { "N/A" }
$OSLastBoot        = try { $OSInfo.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss") } catch { "N/A" }
$Uptime            = try { (Get-Date) - $OSInfo.LastBootUpTime }          catch { $null }
$UptimeStr         = if ($Uptime) { "{0}d {1}h {2}m" -f [int]$Uptime.TotalDays, $Uptime.Hours, $Uptime.Minutes } else { "N/A" }

# Windows Update Build Revision & edition
$WinReg            = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
$UBR               = $WinReg.UBR
$DisplayVersion    = $WinReg.DisplayVersion
$OSEdition         = $WinReg.EditionID
$FullBuild         = if ($UBR) { "$OSBuild.$UBR" } else { "$OSBuild" }

# Hardware
$CSInfo            = Get-WmiObject Win32_ComputerSystem
$Manufacturer      = $CSInfo.Manufacturer
$Model             = $CSInfo.Model
$TotalRAMGB        = [math]::Round($CSInfo.TotalPhysicalMemory / 1GB, 1)
$SystemType        = switch ($CSInfo.SystemType) {
    "x64-based PC"  { "x64" } "x86-based PC" { "x86" } "ARM64-based PC" { "ARM64" } default { $CSInfo.SystemType }
}
$DomainName        = $CSInfo.Domain
$DomainRole        = switch ($CSInfo.DomainRole) {
    0 { "Standalone Workstation" } 1 { "Member Workstation" }
    2 { "Standalone Server" }      3 { "Member Server" }
    4 { "Backup Domain Controller" } 5 { "Primary Domain Controller" }
    default { "Unknown" }
}

# CPU
$CPUInfo           = Get-WmiObject Win32_Processor | Select-Object -First 1
$CPUName           = $CPUInfo.Name.Trim()
$CPUCores          = $CPUInfo.NumberOfCores
$CPUThreads        = $CPUInfo.NumberOfLogicalProcessors

# System disk
$SysDrive          = $env:SystemDrive
$DiskInfo          = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $SysDrive }
$DiskFreeGB        = if ($DiskInfo) { [math]::Round($DiskInfo.FreeSpace / 1GB, 1) } else { "N/A" }
$DiskSizeGB        = if ($DiskInfo) { [math]::Round($DiskInfo.Size / 1GB, 1) } else { "N/A" }

# Network adapters (active, IPv4 only)
$NetAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -and $_.IPAddress } |
    ForEach-Object {
        [PSCustomObject]@{
            Description = $_.Description
            IPAddress   = ($_.IPAddress | Where-Object { $_ -notmatch ':' }) -join ", "
            MACAddress  = $_.MACAddress
            DHCPEnabled = if ($_.DHCPEnabled) { "Yes" } else { "No" }
            DefaultGW   = ($_.DefaultIPGateway -join ", ")
            DNSServers  = ($_.DNSServerSearchOrder -join ", ")
        }
    }

# PowerShell & .NET
$PSVer             = $PSVersionTable.PSVersion.ToString()
$DotNetBuild       = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Release
$DotNetStr         = if     ($DotNetBuild -ge 533320) { "4.8.1+" }
                     elseif ($DotNetBuild -ge 528040) { "4.8" }
                     elseif ($DotNetBuild -ge 461808) { "4.7.2" }
                     else                             { "4.x (release $DotNetBuild)" }

# GSA client detection
$AllDrivers        = Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq 'Running' }
$AllServices       = Get-Service -ErrorAction SilentlyContinue

# Registry — version, install date, GUID
$GsaRegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
$GsaReg = $GsaRegPaths | ForEach-Object {
    Get-ChildItem $_ -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Global Secure Access Client*" -and $_.SystemComponent -ne 1 }
} | Select-Object -First 1

# If SystemComponent filtered it out, grab it anyway for version
$GsaRegFull = $GsaRegPaths | ForEach-Object {
    Get-ChildItem $_ -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq "Global Secure Access Client" }
} | Select-Object -First 1

$GsaVersion     = $GsaRegFull.DisplayVersion
$GsaInstallDate = if ($GsaRegFull.InstallDate) { 
    try { [datetime]::ParseExact($GsaRegFull.InstallDate,"yyyyMMdd",$null).ToString("yyyy-MM-dd") } catch { $GsaRegFull.InstallDate }
} else { "N/A" }
$GsaProductCode = $GsaRegFull.PSChildName
$GsaPublisher   = $GsaRegFull.Publisher

# Install path from service binary
$GsaServiceWmi  = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq "GlobalSecureAccessEngineService" }
$GsaInstallPath = if ($GsaServiceWmi) {
    $GsaServiceWmi.PathName -replace '"','' | Split-Path -Parent
} else { "Not found" }

# File version from exe
$GsaFileVersion = if ($GsaInstallPath -and (Test-Path "$GsaInstallPath\GlobalSecureAccessEngineService.exe")) {
    (Get-Item "$GsaInstallPath\GlobalSecureAccessEngineService.exe").VersionInfo.FileVersion
} else { $null }

# All 4 GSA services
$GsaServiceNames = @(
    "GlobalSecureAccessClientManagerService",
    "GlobalSecureAccessEngineService",
    "GlobalSecureAccessForwardingProfileService",
    "GlobalSecureAccessTunnelingService"
)
$GsaServices = $GsaServiceNames | ForEach-Object {
    $svcName = $_
    $svc = $AllServices | Where-Object { $_.Name -eq $svcName }
    [PSCustomObject]@{
        Name        = $svcName
        DisplayName = if ($svc) { $svc.DisplayName } else { $svcName }
        Status      = if ($svc) { $svc.Status.ToString() } else { "Not Found" }
        StartType   = if ($svc) { try { (Get-Service $svcName | Select-Object -Exp StartType).ToString() } catch { "N/A" } } else { "N/A" }
    }
}

# Driver
$GsaDriverObj = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -eq "GlobalSecureAccessDriver" }
$GsaDriverStatus = if ($GsaDriverObj) { "$($GsaDriverObj.State) / $($GsaDriverObj.Status)" } else { "Not Found" }

# Tunnel channel connectivity from event log (last event per channel)
$GsaChannels = @()
$GsaLastError = $null
try {
    $channelNames = @("M365","Internet","Private","Entra")
    $recentEvents = Get-WinEvent -LogName "Microsoft-Windows-Global Secure Access Client-Operational" -MaxEvents 500 -ErrorAction Stop
    foreach ($ch in $channelNames) {
        $ev = $recentEvents | Where-Object { $_.Message -like "*Channel Name: $ch,*" } | Select-Object -First 1
        if ($ev) {
            $connected = $ev.Message -match "GRPC_CHANNEL_READY|succeeded"
            $GsaChannels += [PSCustomObject]@{
                Channel   = $ch
                Status    = if ($connected) { "Connected" } else { "Disconnected" }
                LastSeen  = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                EventId   = $ev.Id
            }
        } else {
            $GsaChannels += [PSCustomObject]@{ Channel=$ch; Status="No recent event"; LastSeen="N/A"; EventId="" }
        }
    }
    $GsaLastError = ($recentEvents | Where-Object { $_.Level -eq 2 } | Select-Object -First 1)
} catch {
    $GsaChannels += [PSCustomObject]@{ Channel="N/A"; Status="Event log unavailable"; LastSeen="N/A"; EventId="" }
}

# Overall GSA install status
$GsaInstalled   = $null -ne $GsaVersion
$GsaAllSvcsOk   = ($GsaServices | Where-Object { $_.Status -ne "Running" }).Count -eq 0
$GsaHealthy     = $GsaInstalled -and $GsaAllSvcsOk -and ($GsaChannels | Where-Object { $_.Status -eq "Connected" }).Count -gt 0
$GsaHealth      = if (-not $GsaInstalled) { "Not Installed" }
                  elseif ($GsaHealthy)    { "Healthy" }
                  elseif ($GsaAllSvcsOk)  { "Installed - check connectivity" }
                  else                    { "Degraded - service(s) not running" }

# WFP callouts (requires admin)
$WfpCallouts = @()
$WfpProviders = @()
$WfpFilters = @()
if ($IsAdmin) {
    $wfpFile = "$env:TEMP\wfpstate_gsareport.xml"
    netsh wfp show state file="$wfpFile" | Out-Null
    if (Test-Path $wfpFile) {
        try {
            [xml]$wfp = Get-Content $wfpFile -ErrorAction Stop
            $WfpCallouts = $wfp.wfpstate.callouts.item | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.displayData.name
                    Description = $_.displayData.description
                    Key         = $_.calloutKey
                }
            }
            $WfpProviders = $wfp.wfpstate.providers.item | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.displayData.name
                    Description = $_.displayData.description
                    Flags       = $_.flags
                    Key         = $_.providerKey
                }
            }
        } catch { }
        Remove-Item $wfpFile -Force -ErrorAction SilentlyContinue
    }
}

# ilowfp.sys specific check
$IlowfpRunning = $AllDrivers | Where-Object { $_.Name -eq 'ilowfp' }

# ─── Match against known vendors ─────────────────────────────────────────────
$Findings = @()
foreach ($vendor in $KnownVendors) {
    $matchedDrivers  = @()
    $matchedServices = @()
    $matchedWfp      = @()

    foreach ($d in $vendor.Drivers) {
        $hit = $AllDrivers | Where-Object { $_.Name -like "*$d*" -or $_.DisplayName -like "*$d*" }
        if ($hit) { $matchedDrivers += $hit | ForEach-Object { $_.Name } }
    }
    foreach ($s in $vendor.Services) {
        $hit = $AllServices | Where-Object { $_.Name -like "*$s*" -or $_.DisplayName -like "*$s*" }
        if ($hit) { $matchedServices += $hit | ForEach-Object { $_.DisplayName } }
    }
    if ($WfpProviders.Count -gt 0) {
        $matchedWfp = $WfpProviders | Where-Object {
            $name = $_.Name
            $vendor.Name -split '/' | ForEach-Object { if ($name -like "*$_*") { $true } }
        } | ForEach-Object { $_.Name }
    }

    $detected = ($matchedDrivers.Count + $matchedServices.Count + $matchedWfp.Count) -gt 0
    if ($detected) {
        $Findings += [PSCustomObject]@{
            Vendor          = $vendor.Name
            Risk            = $vendor.Risk
            Description     = $vendor.Desc
            MatchedDrivers  = $matchedDrivers -join ", "
            MatchedServices = $matchedServices -join ", "
            MatchedWfp      = $matchedWfp -join ", "
        }
    }
}

# Overall risk
$OverallRisk = "None"
if ($Findings | Where-Object { $_.Risk -eq "High" }) { $OverallRisk = "High" }
elseif ($Findings | Where-Object { $_.Risk -eq "Medium" }) { $OverallRisk = "Medium" }
elseif ($Findings | Where-Object { $_.Risk -eq "Low" }) { $OverallRisk = "Low" }

# Non-MS drivers (for engineering view)
$NonMsDrivers = $AllDrivers | ForEach-Object {
    $path = $_.PathName -replace '"',''
    $signer = "Unknown"
    if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
        $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
        if ($sig.SignerCertificate) {
            $signer = $sig.SignerCertificate.Subject -replace '.*CN=([^,]+).*','$1'
        }
    }
    [PSCustomObject]@{
        Name        = $_.Name
        DisplayName = $_.DisplayName
        Signer      = $signer
        Path        = $path
    }
} | Where-Object { $_.Signer -notmatch 'Microsoft' -and $_.Signer -ne '' }

# ─── Build JSON data blobs for HTML ──────────────────────────────────────────
function ConvertTo-SafeJson($obj) {
    $arr = @($obj | Where-Object { $_ -ne $null })
    if ($arr.Count -eq 0) { return "[]" }
    $json = ($arr | ConvertTo-Json -Depth 5 -Compress) -replace '</', '<\/'
    if ($arr.Count -eq 1 -and $json -notmatch '^\[') { return '[' + $json + ']' }
    return $json
}
function ConvertTo-SafeJsonObject($hashtable) {
    return ($hashtable | ConvertTo-Json -Depth 5 -Compress) -replace '</', '<\/'
}

$jsonFindings      = ConvertTo-SafeJson @($Findings)
$jsonWfpCallouts   = ConvertTo-SafeJson @($WfpCallouts)
$jsonWfpProviders  = ConvertTo-SafeJson @($WfpProviders)
$jsonNonMsDrivers  = ConvertTo-SafeJson @($NonMsDrivers)
$jsonNetAdapters   = ConvertTo-SafeJson @($NetAdapters)
$jsonGsaServices   = ConvertTo-SafeJson @($GsaServices)
$jsonGsaChannels   = ConvertTo-SafeJson @($GsaChannels)
$jsonMeta = ConvertTo-SafeJsonObject @{
    # Scan metadata
    reportTime       = $ReportTime
    reportTimeUtc    = $ReportTimeUtc
    isAdmin          = $IsAdmin
    overallRisk      = $OverallRisk
    findingCount     = $Findings.Count
    wfpCalloutCount  = $WfpCallouts.Count
    wfpProviderCount = $WfpProviders.Count
    ilowfpDetected   = ($null -ne $IlowfpRunning)
    # Identity
    machine          = $MachineName
    user             = $User
    userFull         = $UserFull
    joinType         = $JoinType
    entraTenantName  = $EntraTenantName
    entraTenantId    = $EntraTenantId
    entraPrtStatus   = $EntraPrtStatus
    domain           = $DomainName
    domainRole       = $DomainRole
    # OS
    os               = $OSCaption
    osVersion        = $OSVersion
    osBuild          = $FullBuild
    osDisplayVersion = "$DisplayVersion"
    osEdition        = "$OSEdition"
    osInstallDate    = $OSInstallDate
    osLastBoot       = $OSLastBoot
    osUptime         = $UptimeStr
    # Hardware
    manufacturer     = $Manufacturer
    model            = $Model
    cpu              = $CPUName
    cpuCores         = "$CPUCores cores / $CPUThreads threads"
    ramGB            = "$TotalRAMGB GB"
    systemType       = $SystemType
    diskSystem       = "$DiskFreeGB GB free of $DiskSizeGB GB ($SysDrive)"
    # Runtime
    psVersion        = $PSVer
    dotNetVersion    = $DotNetStr
    # GSA
    gsaInstalled     = $GsaInstalled
    gsaVersion       = "$GsaVersion"
    gsaFileVersion   = "$GsaFileVersion"
    gsaInstallDate   = $GsaInstallDate
    gsaInstallPath   = $GsaInstallPath
    gsaProductCode   = "$GsaProductCode"
    gsaPublisher     = "$GsaPublisher"
    gsaDriverStatus  = $GsaDriverStatus
    gsaHealth        = $GsaHealth
    gsaStatus        = if ($GsaInstalled) { "v$GsaVersion - $GsaHealth" } else { "Not detected" }
}

# ─── HTML Template ────────────────────────────────────────────────────────────
$html = @'

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>GSA Client - WFP Conflict Report</title>
<script>
  (() => {
    const param = new URLSearchParams(window.location.search).get("clawpilotTheme");
    const theme = param || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
  })();
</script>
<style>
:root {
  color-scheme: light;
  --cp-bg: #f7f4ef;
  --cp-bg-elevated: #fcfbf8;
  --cp-surface: #ffffff;
  --cp-surface-soft: #f5f5f5;
  --cp-border: #dedede;
  --cp-border-strong: #919191;
  --cp-text: #242424;
  --cp-text-muted: #5c5c5c;
  --cp-text-soft: #6f6f6f;
  --cp-accent: #b11f4b;
  --cp-accent-hover: #9a1a41;
  --cp-accent-soft: rgba(177,31,75,0.08);
  --cp-accent-fg: #ffffff;
  --cp-success: #16a34a;
  --cp-danger: #dc2626;
  --cp-warning: #f59e0b;
  --cp-link: #0078d4;
  --cp-shadow: 0 18px 48px rgba(0,0,0,0.12);
  --cp-overlay: rgba(255,255,255,0.8);
  --cp-panel: rgba(255,255,255,0.86);
  --cp-panel-strong: rgba(255,255,255,0.96);
  --cp-sheen: rgba(255,255,255,0.55);
  --cp-highlight: rgba(177,31,75,0.12);
}
html[data-theme="dark"] {
  color-scheme: dark;
  --cp-bg: #3d3b3a;
  --cp-bg-elevated: #343231;
  --cp-surface: #292929;
  --cp-surface-soft: #2e2e2e;
  --cp-border: #474747;
  --cp-border-strong: #5f5f5f;
  --cp-text: #dedede;
  --cp-text-muted: #919191;
  --cp-text-soft: #b0b0b0;
  --cp-accent: #fd8ea1;
  --cp-accent-hover: #fb7b91;
  --cp-accent-soft: rgba(253,142,161,0.14);
  --cp-accent-fg: #1a1a1a;
  --cp-success: #4ade80;
  --cp-danger: #f87171;
  --cp-warning: #fbbf24;
  --cp-link: #4da6ff;
  --cp-shadow: 0 18px 48px rgba(0,0,0,0.32);
  --cp-overlay: rgba(41,41,41,0.88);
  --cp-panel: rgba(41,41,41,0.72);
  --cp-panel-strong: rgba(41,41,41,0.96);
  --cp-sheen: rgba(255,255,255,0.04);
  --cp-highlight: rgba(253,142,161,0.12);
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: "Segoe UI", Aptos, Calibri, -apple-system, BlinkMacSystemFont, sans-serif; background: var(--cp-bg); color: var(--cp-text); font-size: 14px; line-height: 1.6; }
a { color: var(--cp-link); }
code, pre { font-family: Consolas, "Courier New", Courier, monospace; }

/* Layout */
.app { max-width: 1100px; margin: 0 auto; padding: 24px 20px 60px; }

/* Header */
.header { display: flex; align-items: center; gap: 16px; margin-bottom: 28px; padding-bottom: 20px; border-bottom: 1px solid var(--cp-border); }
.header-icon { width: 44px; height: 44px; border-radius: 10px; background: var(--cp-accent-soft); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.header-icon svg { width: 24px; height: 24px; stroke: var(--cp-accent); }
.header-title { font-size: 20px; font-weight: 600; color: var(--cp-text); }
.header-sub { font-size: 12px; color: var(--cp-text-muted); margin-top: 2px; }
.header-meta { margin-left: auto; text-align: right; font-size: 12px; color: var(--cp-text-muted); }
.theme-toggle { margin-left: 12px; padding: 6px 12px; border-radius: 0.625rem; border: 1px solid var(--cp-border); background: var(--cp-surface); color: var(--cp-text); cursor: pointer; font-size: 12px; font-family: inherit; }
.theme-toggle:hover { border-color: var(--cp-accent); }

/* Risk Banner */
.risk-banner { border-radius: 16px; padding: 20px 24px; margin-bottom: 24px; display: flex; align-items: center; gap: 20px; box-shadow: 0 0 2px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.14); }
.risk-banner.none  { background: var(--cp-surface); border: 1px solid var(--cp-border); }
.risk-banner.low   { background: rgba(22,163,74,0.08);  border: 1px solid rgba(22,163,74,0.3); }
.risk-banner.medium{ background: rgba(245,158,11,0.08); border: 1px solid rgba(245,158,11,0.3); }
.risk-banner.high  { background: rgba(220,38,38,0.08);  border: 1px solid rgba(220,38,38,0.3); }
.risk-dot { width: 52px; height: 52px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 22px; flex-shrink: 0; }
.risk-dot.none   { background: rgba(100,100,100,0.12); }
.risk-dot.low    { background: rgba(22,163,74,0.15); }
.risk-dot.medium { background: rgba(245,158,11,0.15); }
.risk-dot.high   { background: rgba(220,38,38,0.15); }
.risk-label { font-size: 18px; font-weight: 700; }
.risk-label.none   { color: var(--cp-text-muted); }
.risk-label.low    { color: var(--cp-success); }
.risk-label.medium { color: var(--cp-warning); }
.risk-label.high   { color: var(--cp-danger); }
.risk-desc { font-size: 13px; color: var(--cp-text-soft); margin-top: 3px; }
.risk-stats { margin-left: auto; display: flex; gap: 16px; }
.stat-box { text-align: center; }
.stat-num { font-size: 22px; font-weight: 700; color: var(--cp-text); }
.stat-lbl { font-size: 11px; color: var(--cp-text-muted); text-transform: uppercase; letter-spacing: 0.04em; }

/* Admin warning */
.admin-warn { background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.35); border-radius: 0.625rem; padding: 10px 14px; margin-bottom: 20px; font-size: 13px; color: var(--cp-text); display: flex; align-items: center; gap: 8px; }

/* Tabs */
.tabs { display: flex; gap: 4px; margin-bottom: 20px; border-bottom: 1px solid var(--cp-border); padding-bottom: 0; }
.tab { padding: 8px 16px; border-radius: 0.625rem 0.625rem 0 0; cursor: pointer; font-size: 13px; font-weight: 500; color: var(--cp-text-muted); border: 1px solid transparent; border-bottom: none; user-select: none; transition: color 0.15s; }
.tab:hover { color: var(--cp-text); }
.tab.active { color: var(--cp-accent); border-color: var(--cp-border); border-bottom: 1px solid var(--cp-surface); background: var(--cp-surface); margin-bottom: -1px; }
.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* Cards */
.card { background: var(--cp-surface); border: 1px solid var(--cp-border); border-radius: 16px; padding: 20px 22px; margin-bottom: 16px; box-shadow: 0 0 2px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.14); }
.card-title { font-size: 13px; font-weight: 600; color: var(--cp-text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
.card-title .count-badge { background: var(--cp-accent-soft); color: var(--cp-accent); border-radius: 999px; padding: 1px 8px; font-size: 11px; font-weight: 700; text-transform: none; letter-spacing: 0; }

/* Finding cards */
.finding { border-radius: 12px; border: 1px solid var(--cp-border); padding: 16px 18px; margin-bottom: 12px; }
.finding.high   { border-left: 3px solid var(--cp-danger); }
.finding.medium { border-left: 3px solid var(--cp-warning); }
.finding.low    { border-left: 3px solid var(--cp-success); }
.finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.finding-name { font-weight: 600; font-size: 14px; }
.badge { display: inline-flex; align-items: center; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.badge-high   { background: rgba(220,38,38,0.12);  color: var(--cp-danger); }
.badge-medium { background: rgba(245,158,11,0.12); color: var(--cp-warning); }
.badge-low    { background: rgba(22,163,74,0.12);  color: var(--cp-success); }
.badge-info   { background: var(--cp-accent-soft); color: var(--cp-accent); }
.finding-desc { font-size: 13px; color: var(--cp-text-soft); margin-bottom: 10px; }
.finding-matches { display: flex; flex-wrap: wrap; gap: 8px; }
.match-group { font-size: 12px; }
.match-label { color: var(--cp-text-muted); font-weight: 500; }
.match-val { background: var(--cp-surface-soft); border: 1px solid var(--cp-border); border-radius: 4px; padding: 1px 6px; font-family: Consolas, monospace; font-size: 11px; }

/* Table */
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.data-table th { background: var(--cp-surface-soft); text-align: left; padding: 8px 12px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--cp-text-muted); border-bottom: 1px solid var(--cp-border); }
.data-table td { padding: 8px 12px; border-bottom: 1px solid var(--cp-border); color: var(--cp-text); vertical-align: top; }
.data-table tr:last-child td { border-bottom: none; }
.data-table tr:hover td { background: var(--cp-accent-soft); }
.mono { font-family: Consolas, monospace; font-size: 12px; color: var(--cp-text-soft); }

/* Recommendation list */
.reco-list { list-style: none; }
.reco-list li { display: flex; gap: 10px; padding: 10px 0; border-bottom: 1px solid var(--cp-border); font-size: 13px; }
.reco-list li:last-child { border-bottom: none; }
.reco-icon { flex-shrink: 0; width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; margin-top: 1px; }
.reco-icon.action { background: rgba(220,38,38,0.12); color: var(--cp-danger); }
.reco-icon.info   { background: rgba(0,120,212,0.1);  color: var(--cp-link); }
.reco-icon.ok     { background: rgba(22,163,74,0.12); color: var(--cp-success); }

/* Empty state */
.empty { text-align: center; padding: 40px 20px; color: var(--cp-text-muted); font-size: 13px; }
.empty-icon { font-size: 32px; margin-bottom: 8px; }

/* Collapsible */
details summary { cursor: pointer; padding: 8px 0; font-weight: 500; font-size: 13px; color: var(--cp-text-soft); user-select: none; }
details summary:hover { color: var(--cp-text); }
details[open] summary { color: var(--cp-accent); }

/* ilowfp highlight */
.ilowfp-alert { background: rgba(245,158,11,0.08); border: 1px solid rgba(245,158,11,0.3); border-radius: 0.625rem; padding: 12px 16px; margin-bottom: 16px; font-size: 13px; }

@media (max-width: 600px) {
  .risk-stats { display: none; }
  .header-meta { display: none; }
  #sysinfoGrid { grid-template-columns: 1fr !important; }
}
</style>
</head>
<body>
<div class="app">

  <!-- Header -->
  <div class="header">
    <div class="header-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r="0.5" fill="currentColor"/>
      </svg>
    </div>
    <div>
      <div class="header-title">GSA Client - WFP Conflict Detection Report</div>
      <div class="header-sub">Global Secure Access · Windows Filtering Platform Analysis</div>
    </div>
    <div class="header-meta" id="metaBlock"></div>
    <button class="theme-toggle" onclick="toggleTheme()">- Theme</button>
  </div>

  <!-- Admin warning -->
  <div class="admin-warn" id="adminWarn" style="display:none">
    ⚠️ <strong>Limited scan:</strong> Script was not run as Administrator. WFP callout enumeration is unavailable.
    Re-run with <code>Run as Administrator</code> for full results including kernel-level callout detection.
  </div>

  <!-- ilowfp alert -->
  <div class="ilowfp-alert" id="ilowfpAlert" style="display:none">
    - <strong>ilowfp.sys detected</strong> - An unrecognized WFP callout driver (<code>ilowfp.sys</code>) is running on this machine.
    This driver is not from a known vendor. Investigate its origin via <code>Get-AuthenticodeSignature C:\Windows\System32\drivers\ilowfp.sys</code>
    and verify it is not interfering with GSA traffic.
  </div>

  <!-- Risk Banner -->
  <div class="risk-banner" id="riskBanner">
    <div class="risk-dot" id="riskDot"></div>
    <div>
      <div class="risk-label" id="riskLabel"></div>
      <div class="risk-desc" id="riskDesc"></div>
    </div>
    <div class="risk-stats">
      <div class="stat-box"><div class="stat-num" id="statFindings">0</div><div class="stat-lbl">Conflicts Found</div></div>
      <div class="stat-box"><div class="stat-num" id="statCallouts">0</div><div class="stat-lbl">WFP Callouts</div></div>
      <div class="stat-box"><div class="stat-num" id="statProviders">0</div><div class="stat-lbl">WFP Providers</div></div>
    </div>
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <div class="tab active" onclick="showTab('summary')">Summary</div>
    <div class="tab" onclick="showTab('findings')">Findings</div>
    <div class="tab" onclick="showTab('wfp')">WFP Details</div>
    <div class="tab" onclick="showTab('drivers')">Kernel Drivers</div>
    <div class="tab" onclick="showTab('sysinfo')">System Info</div>
    <div class="tab" onclick="showTab('remediation')">Remediation</div>
  </div>

  <!-- TAB: Summary -->
  <div class="tab-panel active" id="tab-summary">
    <div class="card">
      <div class="card-title">What This Report Shows</div>
      <p style="font-size:13px;color:var(--cp-text-soft);line-height:1.7">
        This report scans for kernel-mode WFP (Windows Filtering Platform) callout drivers and services
        that are known to conflict with the <strong>Microsoft Global Secure Access (GSA) client</strong>.
        GSA uses a WFP callout driver to intercept and tunnel traffic. When another product registers
        competing callouts at the same network layers, traffic can be silently dropped, tunnels fail to
        establish, or the machine may become unstable.
      </p>
    </div>

    <div class="card" id="summaryFindings">
      <div class="card-title">Detected Conflicts <span class="count-badge" id="summaryBadge">0</span></div>
      <div id="summaryList"></div>
    </div>

    <div class="card">
      <div class="card-title">Quick Machine Snapshot</div>
      <div id="machineTable"></div>
    </div>
  </div>

  <!-- TAB: Findings -->
  <div class="tab-panel" id="tab-findings">
    <div id="findingsList"></div>
    <div class="empty" id="findingsEmpty" style="display:none">
      <div class="empty-icon">✅</div>
      No conflicting vendor products detected on this machine.
    </div>
  </div>

  <!-- TAB: WFP Details -->
  <div class="tab-panel" id="tab-wfp">
    <div id="wfpAdminNote" style="display:none;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.3);border-radius:0.625rem;padding:12px 16px;margin-bottom:16px;font-size:13px">
      ⚠️ <strong>Administrator elevation required</strong> — WFP callout and provider data is only available when the script
      is run as Administrator (<code>netsh wfp show state</code>). Re-run with elevated privileges to see all registered
      WFP callout drivers and providers, including those from detected conflicting products.
    </div>
    <div class="card">
      <div class="card-title">WFP Callout Drivers <span class="count-badge" id="calloutBadge">0</span></div>
      <p style="font-size:12px;color:var(--cp-text-muted);margin-bottom:12px">
        Kernel-mode callout drivers registered with the Windows Filtering Platform engine. Competing callouts at
        <code>ALE_CONNECT_REDIRECT</code> / <code>ALE_AUTH_CONNECT</code> layers directly interfere with GSA traffic steering.
      </p>
      <div id="calloutTable"></div>
    </div>
    <div class="card">
      <div class="card-title">WFP Providers <span class="count-badge" id="providerBadge">0</span></div>
      <p style="font-size:12px;color:var(--cp-text-muted);margin-bottom:12px">
        WFP providers group callouts and filters by vendor. Multiple providers competing at the same layers can cause
        filter weight conflicts that silently drop or misroute traffic.
      </p>
      <div id="providerTable"></div>
    </div>
  </div>

  <!-- TAB: Kernel Drivers -->
  <div class="tab-panel" id="tab-drivers">
    <div class="card">
      <div class="card-title">Non-Microsoft Running Kernel Drivers <span class="count-badge" id="driverBadge">0</span></div>
      <p style="font-size:12px;color:var(--cp-text-muted);margin-bottom:12px">
        All running kernel-mode drivers not signed by Microsoft. Any of these registering WFP callouts could interfere with GSA.
      </p>
      <div id="driverTable"></div>
    </div>
  </div>

  <!-- TAB: System Info -->
  <div class="tab-panel" id="tab-sysinfo">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px" id="sysinfoGrid">
      <div class="card" id="siIdentity">
        <div class="card-title">Identity</div>
        <div id="siIdentityTable"></div>
      </div>
      <div class="card" id="siOS">
        <div class="card-title">Operating System</div>
        <div id="siOSTable"></div>
      </div>
      <div class="card" id="siHW">
        <div class="card-title">Hardware</div>
        <div id="siHWTable"></div>
      </div>
      <div class="card" id="siRuntime">
        <div class="card-title">Runtime &amp; Environment</div>
        <div id="siRuntimeTable"></div>
      </div>
    </div>

    <!-- GSA Client full card — full width -->
    <div class="card" style="margin-top:0">
      <div class="card-title">Global Secure Access Client <span id="gsaHealthBadge"></span></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div>
          <div style="font-size:11px;font-weight:600;color:var(--cp-text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Installation</div>
          <div id="gsaInstallTable"></div>
        </div>
        <div>
          <div style="font-size:11px;font-weight:600;color:var(--cp-text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Tunnel Channels</div>
          <div id="gsaChannelTable"></div>
        </div>
      </div>
      <div style="margin-top:16px">
        <div style="font-size:11px;font-weight:600;color:var(--cp-text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Services</div>
        <div id="gsaServicesTable"></div>
      </div>
    </div>

    <div class="card" style="margin-top:0">
      <div class="card-title">Network Adapters <span class="count-badge" id="netBadge">0</span></div>
      <div id="netTable"></div>
    </div>
  </div>

  <!-- TAB: Remediation -->
  <div class="tab-panel" id="tab-remediation">
    <div class="card">
      <div class="card-title">Recommended Actions</div>
      <ul class="reco-list" id="recoList"></ul>
    </div>
    <div class="card">
      <div class="card-title">General Guidance</div>
      <ul class="reco-list">
        <li><div class="reco-icon info">ℹ</div><div>Contact conflicting vendor support for a GSA/Microsoft Entra coexistence guide or exclusion configuration.</div></li>
        <li><div class="reco-icon info">ℹ</div><div>Disable overlapping modules in the 3rd-party product (e.g., turn off its network proxy or web filter if GSA handles that).</div></li>

        <li><div class="reco-icon info">ℹ</div><div>Reference: <a href="https://learn.microsoft.com/en-us/entra/global-secure-access/troubleshoot-global-secure-access-client-advanced-diagnostics" target="_blank">GSA Client Known Issues - Microsoft Learn</a></div></li>
        <li><div class="reco-icon info">ℹ</div><div>Re-run this report as <strong>Administrator</strong> to get full WFP callout layer enumeration and more accurate results.</div></li>
      </ul>
    </div>

    <div class="card">
      <div class="card-title">Diagnostic Commands</div>
      <pre style="background:var(--cp-surface-soft);border:1px solid var(--cp-border);border-radius:8px;padding:14px;font-size:12px;overflow-x:auto;line-height:1.7"># Full WFP state dump (run as Admin)
netsh wfp show state file=C:\temp\wfpstate.xml

# Check WFP filter weights and layers
netsh wfp show filters file=C:\temp\wfpfilters.xml

# Verify GSA tunnel driver
Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "*global*secure*" -or $_.DisplayName -like "*GSA*" }

# Investigate unknown driver signature
Get-AuthenticodeSignature C:\Windows\System32\drivers\ilowfp.sys

# List all running non-MS drivers
Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
    $sig = (Get-AuthenticodeSignature ($_.PathName -replace '"','') -EA SilentlyContinue).SignerCertificate.Subject
    [PSCustomObject]@{ Name=$_.Name; Signer=$sig }
} | Where-Object { $_.Signer -notmatch 'Microsoft' }</pre>
    </div>
  </div>

</div><!-- /app -->

<script>
// ─── Embedded data ────────────────────────────────────────────────────────────
const META        = ##META##;
const FINDINGS    = ##FINDINGS##;
const CALLOUTS    = ##CALLOUTS##;
const PROVIDERS   = ##PROVIDERS##;
const DRIVERS     = ##DRIVERS##;
const NET_ADAPTERS= ##NET_ADAPTERS##;
const GSA_SERVICES= ##GSA_SERVICES##;
const GSA_CHANNELS= ##GSA_CHANNELS##;

// ─── Theme ────────────────────────────────────────────────────────────────────
function toggleTheme() {
  const cur = document.documentElement.getAttribute("data-theme");
  document.documentElement.setAttribute("data-theme", cur === "dark" ? "light" : "dark");
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.getElementById("tab-" + name).classList.add("active");
  const tabs = document.querySelectorAll(".tab");
  const map = { summary:0, findings:1, wfp:2, drivers:3, sysinfo:4, remediation:5 };
  tabs[map[name]].classList.add("active");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function esc(s) {
  if (!s) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function riskClass(r) { return (r||"none").toLowerCase(); }
function badgeHtml(risk) {
  const r = (risk||"").toLowerCase();
  return `<span class="badge badge-`+r+`">`+esc(risk)+`</span>`;
}
function makeTable(cols, rows, emptyMsg) {
  if (!rows || rows.length === 0) return `<div class="empty"><div class="empty-icon">-</div>${emptyMsg||"No data"}</div>`;
  let h = `<table class="data-table"><thead><tr>` + cols.map(c=>`<th>${esc(c.label)}</th>`).join("") + `</tr></thead><tbody>`;
  rows.forEach(r => {
    h += `<tr>` + cols.map(c => {
      const v = r[c.key] != null ? r[c.key] : "";
      const cls = c.mono ? ' class="mono"' : '';
      return `<td${cls}>${c.html ? c.html(v,r) : esc(String(v))}</td>`;
    }).join("") + `</tr>`;
  });
  return h + `</tbody></table>`;
}
function kvTable(rows) {
  return `<table class="data-table">` +
    rows.map(([k,v]) => `<tr><td style="font-weight:600;width:150px;white-space:nowrap">${esc(k)}</td><td>${v}</td></tr>`).join("") +
    `</table>`;
}

// ─── Risk banner ──────────────────────────────────────────────────────────────
const riskEmoji = { none:"OK", low:"LOW", medium:"MED", high:"HIGH" };
const riskText  = {
  none:   "No conflicts detected - GSA Client should operate normally.",
  low:    "Low-risk products detected - monitor for intermittent issues.",
  medium: "Potential conflicts detected - test GSA connectivity carefully.",
  high:   "High-risk conflicts detected - GSA Client may not function correctly."
};
const rc = riskClass(META.overallRisk);
document.getElementById("riskBanner").className = "risk-banner " + rc;
document.getElementById("riskDot").className    = "risk-dot " + rc;
document.getElementById("riskDot").textContent  = riskEmoji[rc] || "?";
document.getElementById("riskLabel").className  = "risk-label " + rc;
document.getElementById("riskLabel").textContent= (META.overallRisk||"None") + " Risk";
document.getElementById("riskDesc").textContent = riskText[rc] || "";
document.getElementById("statFindings").textContent  = META.findingCount || 0;
document.getElementById("statCallouts").textContent  = META.wfpCalloutCount || 0;
document.getElementById("statProviders").textContent = META.wfpProviderCount || 0;

// ─── Header meta ──────────────────────────────────────────────────────────────
document.getElementById("metaBlock").innerHTML =
  `<div style="font-weight:600">${esc(META.machine)}</div>` +
  `<div>${esc(META.userFull || META.user)}</div>` +
  `<div>${esc(META.reportTime)}</div>`;

if (!META.isAdmin) document.getElementById("adminWarn").style.display = "flex";
if (!META.isAdmin) document.getElementById("wfpAdminNote").style.display = "block";
if (META.ilowfpDetected) document.getElementById("ilowfpAlert").style.display = "block";

// ─── Summary tab ──────────────────────────────────────────────────────────────
document.getElementById("summaryBadge").textContent = FINDINGS.length;
const machineRows = [
  ["Machine",        esc(META.machine)],
  ["User",           esc(META.userFull || META.user)],
  ["Join Type",      META.joinType ? esc(META.joinType) : "N/A"],
  ["Domain / Role",  esc((META.domain||"") + (META.domainRole ? " — " + META.domainRole : ""))],
  ["Report Time",    esc(META.reportTime) + `<span style="color:var(--cp-text-muted);font-size:11px;margin-left:8px">${esc(META.reportTimeUtc||"")}</span>`],
  ["OS",             esc(META.os) + (META.osDisplayVersion ? ` <span style="color:var(--cp-text-muted)">(${esc(META.osDisplayVersion)})</span>` : "")],
  ["Build",          `<span class="mono">${esc(META.osBuild)}</span> <span style="color:var(--cp-text-muted);font-size:11px">${esc(META.osEdition||"")}</span>`],
  ["GSA Version",    META.gsaInstalled
                      ? `<strong>${esc(META.gsaVersion)}</strong> <span style="color:var(--cp-text-muted);font-size:11px">${esc(META.gsaInstallDate ? "installed " + META.gsaInstallDate : "")}</span>`
                      : '<span style="color:var(--cp-danger)">Not Installed</span>'],
  ["GSA Health",     esc(META.gsaHealth||"Unknown")],
  ["Admin Scan",     META.isAdmin ? "Yes — full WFP callout data available" : "No — re-run as Administrator for complete results"],
  ["Overall Risk",   META.overallRisk || "None"],
];
document.getElementById("machineTable").innerHTML = kvTable(machineRows);

const summaryList = document.getElementById("summaryList");
if (FINDINGS.length === 0) {
  summaryList.innerHTML = `<div class="empty"><div class="empty-icon">-</div>No known conflicting products detected.</div>`;
} else {
  summaryList.innerHTML = FINDINGS.map(f =>
    `<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--cp-border)">
      ${badgeHtml(f.Risk)}
      <strong style="font-size:13px">${esc(f.Vendor)}</strong>
      <span style="font-size:12px;color:var(--cp-text-soft)">${esc(f.MatchedDrivers||f.MatchedServices||"")}</span>
    </div>`
  ).join("") + `<div style="padding-top:10px;font-size:12px;color:var(--cp-text-muted)">Switch to the <strong>Findings</strong> tab for full details and the <strong>Remediation</strong> tab for next steps.</div>`;
}

// ─── Findings tab ─────────────────────────────────────────────────────────────
const findingsList = document.getElementById("findingsList");
if (FINDINGS.length === 0) {
  document.getElementById("findingsEmpty").style.display = "block";
} else {
  findingsList.innerHTML = FINDINGS.map(f => {
    const rc2 = riskClass(f.Risk);
    const matches = [
      f.MatchedDrivers  ? `<span class="match-group"><span class="match-label">Drivers: </span><span class="match-val">${esc(f.MatchedDrivers)}</span></span>` : "",
      f.MatchedServices ? `<span class="match-group"><span class="match-label">Services: </span><span class="match-val">${esc(f.MatchedServices)}</span></span>` : "",
      f.MatchedWfp      ? `<span class="match-group"><span class="match-label">WFP: </span><span class="match-val">${esc(f.MatchedWfp)}</span></span>` : "",
    ].filter(Boolean).join(" ");
    return `<div class="finding ${rc2}">
      <div class="finding-header">
        <div class="finding-name">${esc(f.Vendor)}</div>
        ${badgeHtml(f.Risk)} <span class="badge badge-info">WFP Conflict</span>
      </div>
      <div class="finding-desc">${esc(f.Description)}</div>
      <div class="finding-matches">${matches || '<span style="color:var(--cp-text-muted);font-size:12px">No specific driver/service match - detected via name pattern.</span>'}</div>
    </div>`;
  }).join("");
}

// ─── WFP tab ──────────────────────────────────────────────────────────────────
document.getElementById("calloutBadge").textContent  = CALLOUTS.length;
document.getElementById("providerBadge").textContent = PROVIDERS.length;
document.getElementById("calloutTable").innerHTML = makeTable(
  [{label:"Name",key:"Name"},{label:"Description",key:"Description"},{label:"Key",key:"Key",mono:true}],
  CALLOUTS, "No WFP callouts found. Run as Administrator to enumerate callouts."
);
document.getElementById("providerTable").innerHTML = makeTable(
  [{label:"Provider",key:"Name"},{label:"Description",key:"Description"},{label:"Flags",key:"Flags",mono:true}],
  PROVIDERS, "No WFP providers found. Run as Administrator to enumerate providers."
);

// ─── Drivers tab ─────────────────────────────────────────────────────────────
document.getElementById("driverBadge").textContent = DRIVERS.length;
document.getElementById("driverTable").innerHTML = makeTable(
  [{label:"Name",key:"Name",mono:true},{label:"Display Name",key:"DisplayName"},{label:"Signer",key:"Signer"},{label:"Path",key:"Path",mono:true}],
  DRIVERS, "No non-Microsoft drivers found."
);

// ─── System Info tab ─────────────────────────────────────────────────────────
document.getElementById("siIdentityTable").innerHTML = kvTable([
  ["Machine Name",    esc(META.machine)],
  ["User (DOMAIN)",   esc(META.userFull || META.user)],
  ["Join Type",       (() => {
      const jt = META.joinType || "Unknown";
      const cls = jt.includes("Entra") ? "low" : jt.includes("Domain") ? "medium" : "high";
      return '<span class="badge badge-' + cls + '">' + esc(jt) + '</span>';
  })()],
  ["Tenant",          META.entraTenantName ? esc(META.entraTenantName) + '<span style="color:var(--cp-text-muted);font-size:11px;margin-left:6px">' + esc(META.entraTenantId) + '</span>' : '<span style="color:var(--cp-text-muted)">N/A</span>'],
  ["Entra PRT",       META.entraPrtStatus ? esc(META.entraPrtStatus) : '<span style="color:var(--cp-text-muted)">N/A</span>'],
  ["Domain",          esc(META.domain||"N/A")],
  ["Domain Role",     esc(META.domainRole||"N/A")],
]);
document.getElementById("siOSTable").innerHTML = kvTable([
  ["OS",              esc(META.os)],
  ["Edition",         esc(META.osEdition||"N/A")],
  ["Version",         `<span class="mono">${esc(META.osVersion||"")}</span>`],
  ["Build",           `<span class="mono">${esc(META.osBuild||"")}</span>` + (META.osDisplayVersion ? ` <span style="color:var(--cp-text-muted)">${esc(META.osDisplayVersion)}</span>` : "")],
  ["Install Date",    esc(META.osInstallDate||"N/A")],
  ["Last Boot",       esc(META.osLastBoot||"N/A")],
  ["Uptime",          esc(META.osUptime||"N/A")],
]);
document.getElementById("siHWTable").innerHTML = kvTable([
  ["Manufacturer",    esc(META.manufacturer||"N/A")],
  ["Model",           esc(META.model||"N/A")],
  ["Architecture",    esc(META.systemType||"N/A")],
  ["CPU",             esc(META.cpu||"N/A")],
  ["CPU Cores",       esc(META.cpuCores||"N/A")],
  ["RAM",             esc(META.ramGB||"N/A")],
  ["System Disk",     esc(META.diskSystem||"N/A")],
]);
document.getElementById("siRuntimeTable").innerHTML = kvTable([
  ["PowerShell",      esc(META.psVersion||"N/A")],
  [".NET Framework",  esc(META.dotNetVersion||"N/A")],
  ["Admin Scan",      META.isAdmin ? "Yes — full WFP data" : "No — limited scan"],
  ["Report Time",     esc(META.reportTime||"")],
  ["Report Time UTC", esc(META.reportTimeUtc||"")],
]);

// ─── GSA Client card ──────────────────────────────────────────────────────────
const gsaHealthClass = { "Healthy":"low", "Not Installed":"high", "Degraded - service(s) not running":"high" };
const ghc = gsaHealthClass[META.gsaHealth] || "medium";
document.getElementById("gsaHealthBadge").outerHTML =
  `<span id="gsaHealthBadge" class="badge badge-${ghc}" style="margin-left:8px">${esc(META.gsaHealth||"Unknown")}</span>`;

document.getElementById("gsaInstallTable").innerHTML = kvTable([
  ["Installed",       META.gsaInstalled ? "Yes" : "No"],
  ["Version",         META.gsaVersion ? `<strong style="font-size:15px">${esc(META.gsaVersion)}</strong>` : '<span style="color:var(--cp-text-muted)">N/A</span>'],
  ["File Version",    META.gsaFileVersion && META.gsaFileVersion !== META.gsaVersion ? `<span class="mono">${esc(META.gsaFileVersion)}</span>` : '<span style="color:var(--cp-text-muted)">same as package</span>'],
  ["Publisher",       esc(META.gsaPublisher||"N/A")],
  ["Install Date",    esc(META.gsaInstallDate||"N/A")],
  ["Install Path",    `<span class="mono" style="font-size:11px">${esc(META.gsaInstallPath||"N/A")}</span>`],
  ["Driver",          esc(META.gsaDriverStatus||"N/A")],
  ["Product Code",    `<span class="mono" style="font-size:11px">${esc(META.gsaProductCode||"N/A")}</span>`],
]);

const chArr = Array.isArray(GSA_CHANNELS) ? GSA_CHANNELS : (GSA_CHANNELS ? [GSA_CHANNELS] : []);
document.getElementById("gsaChannelTable").innerHTML = makeTable(
  [
    { label:"Channel", key:"Channel" },
    { label:"Status",  key:"Status",  html:(v) => {
        const cls = v==="Connected" ? "low" : v==="No recent event" ? "medium" : "high";
        return `<span class="badge badge-${cls}">${esc(v)}</span>`;
    }},
    { label:"Last Event", key:"LastSeen", mono:true },
    { label:"Event ID",   key:"EventId",  mono:true },
  ],
  chArr, "No channel data available."
);

const svcArr = Array.isArray(GSA_SERVICES) ? GSA_SERVICES : (GSA_SERVICES ? [GSA_SERVICES] : []);
document.getElementById("gsaServicesTable").innerHTML = makeTable(
  [
    { label:"Service Name",  key:"Name",        mono:true },
    { label:"Display Name",  key:"DisplayName" },
    { label:"Status",        key:"Status", html:(v) => {
        const cls = v==="Running" ? "low" : "high";
        return `<span class="badge badge-${cls}">${esc(v)}</span>`;
    }},
    { label:"Start Type",    key:"StartType" },
  ],
  svcArr, "No GSA services found."
);

// Network adapters
const netArr = Array.isArray(NET_ADAPTERS) ? NET_ADAPTERS : (NET_ADAPTERS ? [NET_ADAPTERS] : []);
document.getElementById("netBadge").textContent = netArr.length;
document.getElementById("netTable").innerHTML = makeTable(
  [
    {label:"Adapter",     key:"Description"},
    {label:"IP Address",  key:"IPAddress",  mono:true},
    {label:"MAC",         key:"MACAddress", mono:true},
    {label:"DHCP",        key:"DHCPEnabled"},
    {label:"Default GW",  key:"DefaultGW",  mono:true},
    {label:"DNS Servers", key:"DNSServers",  mono:true},
  ],
  netArr, "No active network adapters found."
);

// ─── Remediation tab ──────────────────────────────────────────────────────────
const vendorRemediation = {
  "Forcepoint":       "Disable Forcepoint Web Security network proxy / SSL inspection on devices running GSA, or configure Forcepoint to exclude Microsoft Entra and M365 traffic from its WFP redirect callout.",
  "Check Point":      "In Check Point Endpoint Security, disable the 'Full Disk Encryption' network component or configure a firewall exclusion rule to allow GSA tunnel traffic without interception.",
  "Skyhigh/McAfee":   "In McAfee/Trellix/Skyhigh console, disable the 'Web Gateway' or 'Client Proxy' component, or add the GSA service account and driver to the exclusion list.",
  "Zscaler":          "Zscaler Client Connector and GSA cannot run simultaneously on the same device. Disable Zscaler ZIA/ZPA on devices deployed with GSA, or coordinate with Zscaler for a coexistence policy.",
  "Netskope":         "Configure Netskope steering exceptions to bypass Microsoft Entra ID, M365, and Private Access traffic. Contact Netskope support for a GSA coexistence configuration guide.",
  "Symantec/Broadcom":"Disable Symantec Endpoint Protection's 'Network Threat Protection' module or add the GlobalSecureAccessDriver to the excluded drivers list in SEP policy.",
  "CrowdStrike":      "CrowdStrike Falcon generally coexists with GSA. If issues arise, verify that Falcon sensor network telemetry is not set to block/redirect mode. Contact CrowdStrike for a GSA exclusion policy.",
  "SentinelOne":      "In SentinelOne console, add GlobalSecureAccessDriver and its associated binaries to the exclusion list. Enable 'Interoperability mode' if available for your agent version.",
  "Palo Alto Prisma":  "GlobalProtect VPN and GSA Client cannot run on the same device simultaneously. Disable GlobalProtect or Prisma Access on GSA-managed devices, or use split-tunneling in GlobalProtect to exclude Entra/M365 destinations.",
  "Cisco AnyConnect": "Configure Cisco AnyConnect split-tunneling to exclude Microsoft 365, Entra ID, and GSA tunnel endpoints. Alternatively, disable AnyConnect on devices using GSA for private access.",
  "iboss":            "Configure iboss cloud connector to exclude GSA-tunneled traffic from its WFP redirect policy, or disable iboss on devices where GSA handles secure web gateway functionality.",
  "Trellix":          "Disable the Trellix (McAfee Enterprise) 'Endpoint Security - Threat Prevention' network component or configure the DLP policy to exclude GlobalSecureAccessDriver from interception.",
  "OpenVPN":          "OpenVPN tunnel driver (TAP/DCO) and GSA can coexist in many scenarios, but may conflict if OpenVPN routes overlap with GSA-tunneled traffic. Configure OpenVPN split-tunneling to exclude Entra ID and M365 prefixes, or disconnect OpenVPN before establishing GSA tunnels.",
  "WireGuard":        "WireGuard's Wintun driver may conflict with GSA on machines where both tunnel traffic simultaneously. Configure WireGuard to use split-tunneling, excluding Microsoft Entra ID and M365 IP ranges from the WireGuard tunnel.",
  "Cloudflare One":   "Cloudflare One Client (WARP) and GSA Client are both Zero Trust Network Access agents — they cannot safely run simultaneously. Disable Cloudflare WARP on devices enrolled in GSA, or configure WARP split-tunneling to exclude all Microsoft 365, Entra ID, and Private Access traffic. Do NOT run two ZTNA agents concurrently.",
};
const recoList = document.getElementById("recoList");
const recos = [];
if (FINDINGS.length === 0) {
  recos.push({ icon:"ok", text:"No conflicts detected. No immediate action required." });
  recos.push({ icon:"info", text:"Re-run periodically when new security software is installed." });
} else {
  FINDINGS.forEach(f => {
    const severity = f.Risk.toLowerCase();
    const specific = vendorRemediation[f.Vendor];
    const affectedStr = esc(f.MatchedDrivers || f.MatchedServices || "n/a");
    const text = `<strong>${esc(f.Vendor)}</strong> (${esc(f.Risk)} Risk) — Affected: <code>${affectedStr}</code><br>` +
      `<span style="color:var(--cp-text-soft)">${specific ? specific : "Coordinate with your " + esc(f.Vendor) + " admin to configure exclusions or disable overlapping WFP modules."}</span>`;
    recos.push({ icon: severity === "high" ? "action" : "info", text });
  });
  if (!META.isAdmin) {
    recos.push({ icon:"action", text:"Re-run this script as <strong>Administrator</strong> for a complete WFP callout scan — current results may be incomplete." });
  }
}
recoList.innerHTML = recos.map(r =>
  `<li><div class="reco-icon ${r.icon}">${r.icon==="action"?"!":r.icon==="ok"?"✓":"ℹ"}</div><div>${r.text}</div></li>`
).join("");
</script>
</body>
</html>
'@
$html = $html `
    -replace '##META##',         $jsonMeta `
    -replace '##FINDINGS##',     $jsonFindings `
    -replace '##CALLOUTS##',     $jsonWfpCallouts `
    -replace '##PROVIDERS##',    $jsonWfpProviders `
    -replace '##DRIVERS##',      $jsonNonMsDrivers `
    -replace '##NET_ADAPTERS##', $jsonNetAdapters `
    -replace '##GSA_SERVICES##', $jsonGsaServices `
    -replace '##GSA_CHANNELS##', $jsonGsaChannels


# ─── Write file ───────────────────────────────────────────────────────────────
$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
$fullPath = Resolve-Path $OutputPath
Write-Host ""
Write-Host "  ✅ Report generated: $fullPath" -ForegroundColor Green
Write-Host ""
if (!$IsAdmin) {
    Write-Host "  ⚠️  Run as Administrator for full WFP callout data." -ForegroundColor Yellow
}
if ($Findings.Count -gt 0) {
    Write-Host "  - $($Findings.Count) conflicting product(s) detected:" -ForegroundColor Red
    $Findings | ForEach-Object { Write-Host "     - $($_.Vendor) [$($_.Risk)]" -ForegroundColor Yellow }
} else {
    Write-Host "  ✅ No known conflicting products detected." -ForegroundColor Green
}
Write-Host ""
if (-not $NoBrowser) { Start-Process $fullPath }
