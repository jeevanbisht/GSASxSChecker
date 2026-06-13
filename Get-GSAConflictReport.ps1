<#
.SYNOPSIS
    Detects Windows Filtering Platform (WFP) driver conflicts with the Microsoft
    Global Secure Access (GSA) client and generates a self-contained HTML report.

.DESCRIPTION
    Get-GSAConflictReport scans the local machine for kernel-mode WFP callout
    drivers and services from known security vendors (Forcepoint, Check Point,
    Skyhigh, Zscaler, Netskope, Palo Alto, CrowdStrike, SentinelOne, Symantec,
    Cisco Secure Client/AnyConnect, Cisco Umbrella, Cisco Secure Endpoint, Cisco Secure Access,
    Citrix Secure Access, Fortinet FortiClient, Ivanti/Pulse Secure, F5 BIG-IP Edge,
    SonicWall, Sophos, Absolute/NetMotion, Appgate, Akamai EAA, Twingate, iboss,
    Trellix, OpenVPN, WireGuard, Cloudflare One, Tailscale, NetLimiter,
    Perimeter 81, NordLayer, Keeper Connection Manager, Open Systems SASE,
    Barracuda VPN, WatchGuard Mobile VPN, Array Networks VPN, Aruba VIA,
    Digital Guardian, Proofpoint Endpoint DLP, CoSoSys Endpoint Protector,
    ManageEngine DataSecurity Plus, Menlo Security, Ericom Shield,
    ZeroTier, NetBird, Headscale, Cato Networks, VMware Workspace ONE Tunnel,
    BeyondTrust, NordVPN, ExpressVPN, Surfshark,
    Proton VPN, Mullvad VPN, Cita VPN, and more)
    that are known to conflict with the Microsoft Global Secure Access (GSA) client.

    The GSA client uses a WFP callout driver (GlobalSecureAccessDriver) to intercept
    and tunnel network traffic. When multiple products register WFP callouts at the same
    ALE (Application Layer Enforcement) network layers, traffic can be silently
    dropped — a common cause of tunnels failing to establish, traffic being misrouted, or the machine becoming unstable.

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
    Version      : 1.6.0
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

$script:Version = '1.6.0'

# ─── Known conflicting vendors ───────────────────────────────────────────────
$KnownVendors = @(

    # ─── CASB / SWG / SSE ─────────────────────────────────────────────────────
    @{ Name="Forcepoint";     Risk="High";   Drivers=@("fpwfp","fpdodriver","fpepflt","fp_wfp");           Services=@("fpcsvc","FPWFPDriver","ForcePoint");       Desc="Forcepoint Web Security / DLP uses WFP callouts and network interception that may overlap with GSA traffic steering." }
    @{ Name="Check Point";    Risk="High";   Drivers=@("vsdatant","cpfw","cptlsp","cpepflt");              Services=@("CheckPoint","CPDA");           Desc="Check Point Endpoint Security registers network filtering components that may interfere with GSA tunnel processing." }
    @{ Name="Skyhigh/McAfee"; Risk="High";   Drivers=@("mfewfpk","mfefirek","mfehidk","cfwids");          Services=@("McAfee","Skyhigh","mfevtp","masvc");        Desc="Skyhigh and McAfee network security components may overlap with GSA traffic interception and policy enforcement." }
    @{ Name="Zscaler";        Risk="High";   Drivers=@("zscaler","zsa","ZSADriver");                       Services=@("ZSAService","ZscalerService","ZSTunnel");   Desc="Zscaler Client Connector performs traffic steering, DNS control, and tunnel ownership that may conflict with GSA." }
    @{ Name="Netskope";       Risk="High";   Drivers=@("nssdrv","NetskopeFilter","nswfp");                 Services=@("stAgentSvc","NetskopeService");             Desc="Netskope client intercepts network traffic for CASB and SSE functions and may overlap with GSA." }
    @{ Name="Cloudflare One"; Risk="High";   Drivers=@("cfwfpco","cfwfp","cloudflare");                   Services=@("CloudflareWARP","warp-svc");         Desc="Cloudflare One Client (WARP) performs DNS, routing, and traffic steering similar to GSA." }
    @{ Name="iboss";          Risk="Medium"; Drivers=@("iboss","ibossdrv");                               Services=@("ibossService","ibossAgent");                Desc="iboss cloud connector uses network filtering and traffic interception that may overlap with GSA." }

    # ─── Palo Alto ─────────────────────────────────────────────────────
    @{ Name="Palo Alto Prisma / GlobalProtect"; Risk="High"; Drivers=@("pangpd","PanWFP","PanGPA"); Services=@("PanGPS","PanGPA","PrismaAccess"); Desc="GlobalProtect and Prisma Access provide VPN and SSE functions that may conflict with GSA routing and tunnel ownership." }

    # ─── Cisco ─────────────────────────────────────────────────────
    @{ Name="Cisco Secure Client / AnyConnect VPN";    Risk="High";   Drivers=@("acvpnwfp","acsock","vpnva","vpnva64","acnamfd","acwfp"); Services=@("vpnagent","acvpnagent","Cisco AnyConnect Secure Mobility Agent","Cisco Secure Client"); Desc="Cisco VPN client may overlap with GSA routing, DNS, and tunnel establishment." }
    @{ Name="Cisco Secure Client - Umbrella Module";   Risk="High";   Drivers=@("acumbrella","acwfp","csc_umbrella","umbrella");          Services=@("csc_umbrellaagent","Cisco Secure Client - Umbrella","Umbrella_RC","Umbrella Roaming Client"); Desc="Umbrella module provides DNS protection and policy enforcement that may overlap with GSA." }
    @{ Name="Cisco Umbrella Roaming Client";           Risk="High";   Drivers=@("umbrella","opendns","acumbrella");                      Services=@("Umbrella_RC","Umbrella Roaming Client","OpenDNS_Connector"); Desc="Umbrella redirects and protects DNS traffic which may interfere with GSA DNS processing." }
    @{ Name="Cisco Secure Endpoint";                   Risk="Medium"; Drivers=@("ciscoamp","immunetprotect","orbital");      Services=@("CiscoAMP","Cisco Secure Endpoint","ImmunetProtect","CiscoOrbital"); Desc="Cisco endpoint security components may affect network processing depending on policy." }
    @{ Name="Cisco Secure Access";                     Risk="High";   Drivers=@("ciscosecureaccess","ciscoztna","acwfp","acvpnwfp");    Services=@("Cisco Secure Access","CiscoSecureAccess","csc_svr","vpnagent"); Desc="Cisco Secure Access directly overlaps with GSA private access and SSE capabilities." }
    @{ Name="Cisco AnyConnect NVM";                    Risk="Low";    Drivers=@("acnvm","acnamfd","acsock");                            Services=@("acnvmagent","Cisco AnyConnect NVM","Cisco Secure Client NVM"); Desc="Primarily telemetry and visibility focused." }

    # ─── Citrix ─────────────────────────────────────────────────────
    @{ Name="Citrix Secure Access / NetScaler Gateway"; Risk="High"; Drivers=@("nsgwfp","nswfp","nsload","dne","deterministicnetworkenhancer","citrixvpn","ctxvpn"); Services=@("Citrix Secure Access","Citrix Gateway Plugin","NetScaler Gateway Plugin","nsgateway","ctxvpn"); Desc="Citrix VPN and Secure Access clients may overlap with GSA routing, DNS, and private access handling." }

    # ─── Fortinet ────────────────────────────────────────────────────
    @{ Name="Fortinet FortiClient"; Risk="High"; Drivers=@("fortifilter","fortiwf","fortissl","fortivpn","fortidrv"); Services=@("FortiClient","FortiClient Service Scheduler","FortiWF"); Desc="FortiClient provides VPN, ZTNA, filtering, and policy enforcement that may conflict with GSA." }

    # ─── Ivanti / Pulse ──────────────────────────────────────────────────
    @{ Name="Ivanti Secure Access / Pulse Secure"; Risk="High"; Drivers=@("jnprns","dsNcAdpt","pulse","pulsesecure","ivanti"); Services=@("PulseSecureService","Ivanti Secure Access","dsNcService"); Desc="Pulse Secure and Ivanti VPN clients may interfere with GSA tunnel ownership and routing." }

    # ─── F5 ─────────────────────────────────────────────────────
    @{ Name="F5 BIG-IP Edge Client"; Risk="High"; Drivers=@("f5vpn","f5ndis","f5fpclient"); Services=@("BIG-IP Edge Client","F5 Networks VPN Service"); Desc="F5 SSL VPN functionality may overlap with GSA traffic steering." }

    # ─── SonicWall ───────────────────────────────────────────────────
    @{ Name="SonicWall NetExtender"; Risk="High"; Drivers=@("sonicwall","netextender","nxdrv","swvnic"); Services=@("NetExtender","SONICWALL_NetExtender"); Desc="SonicWall SSL VPN client may conflict with GSA routing and DNS handling." }

    # ─── Sophos ─────────────────────────────────────────────────────
    @{ Name="Sophos Connect / Sophos ZTNA"; Risk="High"; Drivers=@("sophos","sophosnetfilter","sophosztna"); Services=@("Sophos Connect Service","Sophos ZTNA","Sophos Network Threat Protection"); Desc="Sophos VPN and ZTNA solutions may overlap with GSA network controls." }

    # ─── Absolute / NetMotion ──────────────────────────────────────────────
    @{ Name="Absolute Secure Access / NetMotion"; Risk="High"; Drivers=@("netmotion","nmfilter","nmdrv","mobility"); Services=@("NetMotion Mobility Client","Absolute Secure Access"); Desc="NetMotion mobility and ZTNA traffic management may conflict with GSA." }

    # ─── Appgate ─────────────────────────────────────────────────────
    @{ Name="Appgate SDP"; Risk="High"; Drivers=@("appgate","appgatesdp","agtun"); Services=@("Appgate SDP Client","Appgate SDP Service"); Desc="Appgate SDP provides private access tunnels that may overlap directly with GSA private access." }

    # ─── Akamai ─────────────────────────────────────────────────────
    @{ Name="Akamai Enterprise Application Access"; Risk="Medium"; Drivers=@("akamai","akamaiaccess"); Services=@("Akamai EAA Client","EAAClient"); Desc="Akamai EAA provides ZTNA functionality and may overlap with GSA private application access." }

    # ─── Modern ZTNA ──────────────────────────────────────────────────
    @{ Name="Twingate"; Risk="Medium"; Drivers=@("twingate","wintun"); Services=@("Twingate","Twingate Service"); Desc="Twingate private access routing may overlap with GSA depending on configuration." }

    # ─── Endpoint Security ───────────────────────────────────────────────
    @{ Name="Trellix";          Risk="High";   Drivers=@("mfewfpk","xagt","HipShieldK");              Services=@("xagt","Trellix","McAfeeDLPAgentService");   Desc="Trellix endpoint and DLP controls may interfere with GSA traffic processing." }
    @{ Name="Symantec/Broadcom"; Risk="Medium"; Drivers=@("symnets","srtspx","SymEvent");              Services=@("SepMasterService","SymNetDrv");             Desc="Symantec network protection components may affect GSA depending on policy." }
    @{ Name="CrowdStrike";      Risk="Low";    Drivers=@("csagent","CrowdStrike");                    Services=@("CSFalconService","CrowdStrike");            Desc="Generally coexists but useful to inventory." }
    @{ Name="SentinelOne";      Risk="Low";    Drivers=@("sentinelmonitor","SentinelAgent","s1filter"); Services=@("SentinelAgent","SentinelOne");              Desc="Generally coexists but may affect networking under some policies." }

    # ─── VPN / Mesh VPN ───────────────────────────────────────────────────
    @{ Name="OpenVPN";  Risk="Medium"; Drivers=@("ovpn-dco","tap_ovpnconnect","tapwindows","ovpnco"); Services=@("OpenVPNService","OpenVPN Connect","ovpnhelper"); Desc="OpenVPN virtual adapters and routing may overlap with GSA." }
    @{ Name="WireGuard"; Risk="Medium"; Drivers=@("wintun","WireGuard","wireguard");                   Services=@("WireGuardTunnel","WireGuardManager");          Desc="WireGuard uses Wintun-based tunneling which may create route ownership conflicts." }
    @{ Name="Tailscale"; Risk="Medium"; Drivers=@("wintun","tailscale");                               Services=@("Tailscale","tailscaled");                      Desc="Tailscale mesh VPN may create overlapping route ownership with GSA." }

    # ─── Traffic Shaping / Monitoring ─────────────────────────────────────────
    @{ Name="NetLimiter"; Risk="Medium"; Drivers=@("nldrv","netlimiter"); Services=@("nlsvc","NetLimiter"); Desc="Traffic shaping and filtering may affect GSA traffic classification." }

    # ─── SSE / ZTNA / SWG (Extended) ──────────────────────────────────────────
    @{ Name="Perimeter 81";            Risk="High";   Drivers=@("perimeter81","p81","wintun");        Services=@("Perimeter81","Perimeter81Service");                    Desc="ZTNA and secure access platform that installs tunnels and traffic steering components similar to GSA." }
    @{ Name="NordLayer";               Risk="High";   Drivers=@("nordlayer","nordlynx","wintun");     Services=@("NordLayer","NordLayerService");                        Desc="Business ZTNA and VPN solution that owns routes and tunnel interfaces." }
    @{ Name="Keeper Connection Manager"; Risk="Medium"; Drivers=@("keeper","keeperztna");             Services=@("Keeper","KeeperConnectionManager");                    Desc="ZTNA capabilities may overlap with GSA private access scenarios." }
    @{ Name="Open Systems SASE";       Risk="High";   Drivers=@("opensystems","osevpn");           Services=@("OpenSystems","OpenSystemsAgent");                      Desc="Managed SASE client performing traffic steering and filtering that may overlap with GSA." }

    # ─── VPN (Extended) ───────────────────────────────────────────────────────
    @{ Name="Barracuda VPN";           Risk="High";   Drivers=@("barracuda","barracudavpn");          Services=@("BarracudaVPN","Barracuda Network Access Client");       Desc="VPN tunnel ownership may conflict with GSA routing and traffic interception." }
    @{ Name="WatchGuard Mobile VPN";   Risk="High";   Drivers=@("wgvpn","watchguardvpn");            Services=@("WatchGuard Mobile VPN","WGVPN");                       Desc="SSL/IPsec VPN client with route ownership that may conflict with GSA." }
    @{ Name="Array Networks VPN";      Risk="Medium"; Drivers=@("arrayvpn","agsslvpn");              Services=@("Array Networks SSL VPN","ArrayVPN");                   Desc="Enterprise SSL VPN client that may overlap with GSA private access." }
    @{ Name="Aruba VIA";               Risk="Medium"; Drivers=@("arubavia");                   Services=@("Aruba VIA","ArubaVIAService");                         Desc="Enterprise VPN client which installs virtual adapters and routes that may conflict with GSA." }

    # ─── DLP / Endpoint Security (Extended) ───────────────────────────────────
    @{ Name="Digital Guardian";        Risk="High";   Drivers=@("dgflt","dgwfp","dgagent");          Services=@("DgService","DigitalGuardian");                         Desc="DLP agent uses kernel filtering and network inspection that may interfere with GSA traffic processing." }
    @{ Name="Proofpoint Endpoint DLP"; Risk="Medium"; Drivers=@("proofpoint","ppwfp");               Services=@("Proofpoint","Proofpoint Endpoint");                    Desc="Endpoint DLP and network monitoring capabilities may affect GSA traffic classification." }
    @{ Name="CoSoSys Endpoint Protector"; Risk="Medium"; Drivers=@("endpointprotector");       Services=@("EndpointProtector","EPPService");                      Desc="Endpoint DLP solution with network controls that may coexist conditionally with GSA." }
    @{ Name="ManageEngine DataSecurity Plus"; Risk="Low"; Drivers=@("manageengine");           Services=@("DataSecurityPlus");                                    Desc="Monitoring and inspection components may coexist but should be inventoried." }

    # ─── Browser Isolation / SWG ──────────────────────────────────────────────
    @{ Name="Menlo Security";          Risk="Medium"; Drivers=@("menlo","menlofilter");              Services=@("MenloSecurity","MenloAgent");                          Desc="Isolation and secure web gateway functions may affect GSA traffic steering depending on configuration." }
    @{ Name="Ericom Shield";           Risk="Medium"; Drivers=@("ericom");                  Services=@("EricomShield","ShieldAgent");                          Desc="Browser isolation and secure access platform that may overlap with GSA internet access routing." }

    # ─── Overlay Networking / Mesh VPN ────────────────────────────────────────
    @{ Name="ZeroTier";                Risk="Medium"; Drivers=@("zerotier","ztvirtual");             Services=@("ZeroTierOne");                                         Desc="Overlay network with virtual adapters and route injection that may conflict with GSA traffic redirection." }
    @{ Name="NetBird";                 Risk="Medium"; Drivers=@("netbird","wintun");                 Services=@("NetBird","NetBirdService");                            Desc="WireGuard-based enterprise mesh networking using Wintun that may create route conflicts with GSA." }
    @{ Name="Headscale";               Risk="Low";    Drivers=@("wintun");                           Services=@("Headscale");                                           Desc="Tailscale-compatible deployments using Wintun adapters; generally low risk but should be inventoried." }

    # ─── SASE / SD-WAN ────────────────────────────────────────────────────────────
    @{ Name="Cato Networks";           Risk="High";   Drivers=@("cato","catovpn","catotunnel","catowfp"); Services=@("CatoClient","CatoNetworks","CatoVPN"); Desc="Cato SASE client performs traffic steering, DNS interception, ZTNA, SWG, and VPN functions that may overlap with Microsoft Global Secure Access routing and policy enforcement." }

    # ─── Enterprise Remote Access / UEM ───────────────────────────────────────────
    @{ Name="VMware Workspace ONE Tunnel"; Risk="High"; Drivers=@("airwatch","workspaceone");            Services=@("VMware Tunnel","Workspace ONE Tunnel");                Desc="Enterprise application tunnel and secure access solution that may overlap with GSA private access routing and policy enforcement." }
    @{ Name="BeyondTrust Secure Remote Access"; Risk="Medium"; Drivers=@("bomgar","beyondtrust");        Services=@("Bomgar","BeyondTrust");                                Desc="Secure remote access solution that may install networking components and affect traffic routing." }

    # ─── Consumer / Commercial VPN ────────────────────────────────────────────────
    @{ Name="NordVPN";                 Risk="Medium"; Drivers=@("nordvpn","nordlynx","wintun","tap-nordvpn"); Services=@("NordVPN Service","NordVPN","nordvpn-service"); Desc="NordVPN uses NordLynx and virtual tunnel adapters that may create route ownership and DNS conflicts." }
    @{ Name="ExpressVPN";              Risk="Medium"; Drivers=@("expressvpn","expressvpntun");           Services=@("ExpressVPN","ExpressVPNSystemService");                Desc="VPN tunnel and DNS ownership may overlap with GSA." }
    @{ Name="Surfshark";               Risk="Medium"; Drivers=@("surfshark","surfsharkwireguard","wintun"); Services=@("Surfshark Service","Surfshark");                    Desc="WireGuard-based VPN client with route ownership." }
    @{ Name="Proton VPN";              Risk="Medium"; Drivers=@("protonvpn","wintun");                  Services=@("ProtonVPN Service","ProtonVPN");                       Desc="VPN tunnel ownership and DNS interception may overlap with GSA." }
    @{ Name="Mullvad VPN";             Risk="Medium"; Drivers=@("mullvad","wintun");                    Services=@("Mullvad VPN","MullvadVPN");                            Desc="WireGuard-based VPN client that may create route conflicts." }
    @{ Name="Cita VPN";                Risk="Medium"; Drivers=@("citavpn","wintun");                    Services=@("CitaVPN","Cita VPN");                                  Desc="Consumer VPN client providing encrypted tunnels and route ownership that may conflict with GSA." }

)

# ─── Collect system data ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "  GSA SxS Checker v$($script:Version)" -ForegroundColor Cyan
Write-Host "  https://github.com/jeevanbisht/GSASxSChecker"
Write-Host ""
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
    toolVersion      = $script:Version
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
      <div class="header-title">GSA Client - Conflict Detection Report</div>
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

  <!-- Disclaimer -->
  <p style="font-size:12px;color:var(--cp-text-soft);line-height:1.6;margin:-8px 0 20px">
    <strong>Note:</strong> This is a discovery and recommendation tool. It can only detect conflicts on the <strong>local machine</strong>. If you have already applied a remediation, you may still continue to see the warnings. Always check the <a href="https://learn.microsoft.com/entra/global-secure-access/" target="_blank" rel="noopener">official Microsoft documentation</a> for the latest guidance.
  </p>

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
        This report detects potential conflicts with the
        <a href="https://learn.microsoft.com/en-us/entra/global-secure-access/" target="_blank" rel="noopener"><strong>Microsoft Global Secure Access (GSA)</strong></a>
        client by identifying coexisting network security products and their associated kernel-mode WFP
        (Windows Filtering Platform) drivers that may interfere with traffic interception, redirection, or
        filtering operations. GSA uses a WFP callout driver to intercept and tunnel traffic. When another
        product registers WFP callouts at the same network layers, traffic can be silently dropped, tunnels
        may fail to establish, or connectivity to protected resources may be degraded.
      </p>
    </div>

    <div class="card" id="summaryFindings">
      <div class="card-title">Detected Conflicts <span class="count-badge" id="summaryBadge">0</span></div>
      <p style="font-size:12px;color:var(--cp-text-muted);line-height:1.6;margin:0 0 10px">
        <strong>Note:</strong> A number of products may share the same underlying drivers (for example
        <code>wintun</code>). The list below may therefore include all potential product names associated with
        a detected driver, even if only one of them is actually installed on this machine.
      </p>
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
        Kernel-mode callout drivers registered with the Windows Filtering Platform engine. Multiple callouts registered at
        <code>ALE_CONNECT_REDIRECT</code> / <code>ALE_AUTH_CONNECT</code> layers can interfere with GSA traffic steering.
      </p>
      <div id="calloutTable"></div>
    </div>
    <div class="card">
      <div class="card-title">WFP Providers <span class="count-badge" id="providerBadge">0</span></div>
      <p style="font-size:12px;color:var(--cp-text-muted);margin-bottom:12px">
        WFP providers group callouts and filters by product. Multiple providers registered at the same layers can cause
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
  `<div>${esc(META.reportTime)}</div>` +
  `<div style="color:var(--cp-text-soft);font-size:11px">GSA SxS Checker v${esc(META.toolVersion)}</div>`;

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
  summaryList.innerHTML =
    `<table class="data-table">
       <thead>
         <tr>
           <th style="width:140px">PotentialConflict</th>
           <th>Driver Name</th>
           <th>Services</th>
           <th style="width:80px">Match</th>
           <th>Product</th>
         </tr>
       </thead>
       <tbody>` +
    FINDINGS.map(f => {
      const svcMatch = (f.MatchedServices && f.MatchedServices.trim() !== "");
      return `<tr>
        <td>${badgeHtml(f.Risk)}</td>
        <td style="font-size:12px;color:var(--cp-text-soft)">${esc(f.MatchedDrivers||"—")}</td>
        <td style="font-size:12px;color:var(--cp-text-soft)">${esc(f.MatchedServices||"—")}</td>
        <td><span class="badge ${svcMatch ? "badge-info" : ""}" style="font-weight:600">${svcMatch ? "Yes" : "No"}</span></td>
        <td><strong style="font-size:13px">${esc(f.Vendor)}</strong></td>
      </tr>`;
    }).join("") +
    `</tbody></table>` +
    `<div style="padding-top:10px;font-size:12px;color:var(--cp-text-muted)">Switch to the <strong>Findings</strong> tab for full details and the <strong>Remediation</strong> tab for next steps.</div>`;
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
  "Zscaler":          "Coexistence is supported across multiple traffic scenarios (GSA for Private/Internet/M365, Zscaler for Internet/Private). Configure Zscaler Client Connector app profile with GSA IP and FQDN bypasses. See: <a href='https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-zscaler-coexistence' target='_blank'>Configure Microsoft and Zscaler for a Unified SASE Solution</a>",
  "Netskope":         "Coexistence is supported across multiple traffic scenarios (GSA for Private/Internet/M365, Netskope for Internet/Private). Configure Netskope Steering Configuration with GSA IP/FQDN bypass exceptions. See: <a href='https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-netskope-coexistence' target='_blank'>SSE coexistence with Microsoft and Netskope</a>",
  "Symantec/Broadcom":"Disable Symantec Endpoint Protection's 'Network Threat Protection' module or add the GlobalSecureAccessDriver to the excluded drivers list in SEP policy.",
  "CrowdStrike":      "CrowdStrike Falcon generally coexists with GSA. If issues arise, verify that Falcon sensor network telemetry is not set to block/redirect mode. Contact CrowdStrike for a GSA exclusion policy.",
  "SentinelOne":      "In SentinelOne console, add GlobalSecureAccessDriver and its associated binaries to the exclusion list. Enable 'Interoperability mode' if available for your agent version.",
  "Palo Alto Prisma / GlobalProtect": "Coexistence is supported across multiple traffic scenarios (GSA for Private/Internet/M365, Prisma for Internet/Private). Configure GlobalProtect split-tunnel exclusions for GSA IPs and FQDNs in Strata Cloud Manager. See: <a href='https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-palo-alto-coexistence' target='_blank'>SSE coexistence with Microsoft and Palo Alto Networks</a>",
  "Cisco Secure Client / AnyConnect VPN": "Split-Include mode only — full-tunnel VPN cannot run simultaneously with GSA. Requires Cisco Secure Client v5.1.10.x+ and post-install acsocktool.exe configuration. See: <a href='https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-cisco-vpn-coexistence' target='_blank'>Coexistence with Cisco VPNs</a>",
  "Cisco Secure Client - Umbrella Module": "DNS-only coexistence — Cisco SWG must be disabled. Add Umbrella IPs as GSA bypass and globalsecureaccess.microsoft.com to Umbrella internal domains. Requires CSC v5.1.10.x+. See: <a href='https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-cisco-coexistence' target='_blank'>Coexistence with Cisco Umbrella</a>",
  "Cisco Umbrella Roaming Client": "DNS-only coexistence — SWG must be disabled. Add Umbrella IPs as GSA bypass and globalsecureaccess.microsoft.com to Umbrella internal domains. See: <a href='https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-cisco-coexistence' target='_blank'>Coexistence with Cisco Umbrella</a>",
  "Cisco Secure Endpoint": "Cisco Secure Endpoint generally coexists with GSA, but network isolation or custom network access control policies may affect tunnel traffic. If GSA connectivity is degraded, verify that Secure Endpoint policy is not blocking or redirecting GlobalSecureAccessDriver. Add GSA executables and drivers to the Secure Endpoint exclusion list.",
  "Cisco Secure Access": "Coexistence is supported across multiple traffic scenarios. Add Cisco IPs + *.zpc.sse.cisco.com as GSA bypass; bypass GSA IPs in Cisco Traffic Steering. Requires CSC v5.1.10.x+. See: <a href='https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-cisco-secure-access-coexistence' target='_blank'>Coexistence with Cisco Secure Access</a>",
  "Cisco AnyConnect NVM": "Cisco AnyConnect Network Visibility Module is primarily a telemetry component with low conflict risk. If GSA tunnel performance is degraded, verify NVM is not set to enforce network policy. Generally safe to coexist; monitor for intermittent issues.",
  "iboss":            "Configure iboss cloud connector to exclude GSA-tunneled traffic from its WFP redirect policy, or disable iboss on devices where GSA handles secure web gateway functionality.",
  "Trellix":          "Disable the Trellix (McAfee Enterprise) 'Endpoint Security - Threat Prevention' network component or configure the DLP policy to exclude GlobalSecureAccessDriver from interception.",
  "OpenVPN":          "OpenVPN tunnel driver (TAP/DCO) and GSA can coexist in many scenarios, but may conflict if OpenVPN routes overlap with GSA-tunneled traffic. Configure OpenVPN split-tunneling to exclude Entra ID and M365 prefixes, or disconnect OpenVPN before establishing GSA tunnels.",
  "WireGuard":        "WireGuard's Wintun driver may conflict with GSA on machines where both tunnel traffic simultaneously. Configure WireGuard to use split-tunneling, excluding Microsoft Entra ID and M365 IP ranges from the WireGuard tunnel.",
  "Tailscale":        "Tailscale uses the Wintun kernel driver for its mesh VPN tunnel, which operates at the same WFP layers as GSA. If you experience connectivity issues, configure Tailscale's split-tunneling to exclude Microsoft 365, Entra ID, and Private Access destinations, or pause the Tailscale connection while GSA tunnels are active.",
  "NetLimiter":       "NetLimiter's kernel-mode WFP driver (nldrv.sys) classifies and shapes traffic per application. This can interfere with how GSA steers traffic into its tunnel. If GSA tunnel connectivity is degraded, try temporarily disabling NetLimiter rules that apply to the GlobalSecureAccess processes, or add an exclusion rule for GlobalSecureAccessDriver and its associated services.",
  "Cloudflare One":   "Cloudflare One Client (WARP) intercepts network traffic at the same WFP layers as GSA Client. Running both simultaneously can cause tunnel failures and traffic routing issues. Configure WARP split-tunneling to exclude Microsoft 365, Entra ID, and Private Access destinations, or disable WARP on devices where GSA is the active network access client.",
  "Citrix Secure Access / NetScaler Gateway": "Citrix Secure Access and NetScaler Gateway VPN clients use WFP callouts or the legacy Deterministic Network Enhancer (DNE) driver for VPN and split-tunnel control. This can conflict with GSA traffic steering and private access. In the Citrix Gateway console, configure split-tunnel policy to exclude Microsoft 365, Entra ID, and GSA-tunneled destinations. On devices where GSA handles private access, disable the Citrix VPN module or switch Citrix to clientless/web-only mode.",
  "Fortinet FortiClient": "FortiClient VPN and ZTNA components may conflict with GSA tunnel ownership and traffic steering. In the FortiClient EMS console, configure split-tunnel to exclude Microsoft 365 and Entra ID destinations. On devices where GSA is the primary ZTNA client, disable the FortiClient VPN and ZTNA modules.",
  "Ivanti Secure Access / Pulse Secure": "Pulse Secure and Ivanti VPN tunnel traffic may conflict with GSA routing. Configure Ivanti split-tunnel policy to exclude Microsoft 365, Entra ID, and Private Access destinations. On GSA-managed devices, disable the Ivanti VPN module or migrate to GSA for private application access.",
  "F5 BIG-IP Edge Client": "F5 SSL VPN creates a virtual network adapter and routing rules that may conflict with GSA. Configure F5 Network Access resource to exclude Microsoft 365 and Entra ID prefixes from the VPN tunnel, or disable F5 Edge Client on devices where GSA handles private access.",
  "SonicWall NetExtender": "SonicWall NetExtender VPN client installs a virtual adapter and may create routing conflicts with GSA. Configure SonicWall split-tunnel to exclude Microsoft 365, Entra ID, and GSA-handled destinations, or disconnect NetExtender on devices actively using GSA tunnels.",
  "Sophos Connect / Sophos ZTNA": "Sophos VPN and ZTNA components may conflict with GSA traffic interception. In Sophos Central, configure split-tunnel for the VPN policy to exclude Microsoft 365 and Entra ID traffic. On devices where GSA handles ZTNA, disable the Sophos ZTNA Gateway connector.",
  "Absolute Secure Access / NetMotion": "NetMotion Mobility performs persistent traffic management that may conflict with GSA routing. Coordinate with your NetMotion/Absolute administrator to configure traffic policy exclusions for Microsoft 365, Entra ID, and GSA-tunneled destinations.",
  "Appgate SDP": "Appgate SDP creates private access tunnels that overlap directly with GSA private access. On devices where GSA provides private application access, disable or remove Appgate SDP. If both must coexist, configure Appgate entitlements to not overlap with resources handled by GSA.",
  "Akamai Enterprise Application Access": "Akamai EAA client provides ZTNA-style application proxying that may overlap with GSA private access. Configure Akamai EAA to exclude applications and destinations already handled by GSA, or consolidate to a single ZTNA client.",
  "Twingate": "Twingate routes private network traffic via its connector, which may conflict with GSA private access routing. Configure Twingate resources to exclude destinations handled by GSA, or disable Twingate on devices where GSA is the designated private access client.",
  "Perimeter 81": "Perimeter 81 installs a WireGuard/IPsec-based tunnel client that may conflict with GSA traffic steering. Configure Perimeter 81 split-tunnel policy to exclude Microsoft 365, Entra ID, and GSA-tunneled destinations, or disable Perimeter 81 on devices where GSA is the active ZTNA client.",
  "NordLayer": "NordLayer owns network routes and tunnel interfaces using WireGuard. Configure NordLayer to use split-tunnel mode, excluding Microsoft 365, Entra ID, and Private Access destinations from its tunnel.",
  "Keeper Connection Manager": "Keeper Connection Manager's ZTNA features may overlap with GSA private access. Review application access policies in Keeper to ensure resources already handled by GSA are excluded from Keeper's tunnel.",
  "Open Systems SASE": "Open Systems SASE client performs traffic steering and filtering similar to GSA. Coordinate with your Open Systems administrator to configure traffic exclusions for Microsoft 365, Entra ID, and GSA-tunneled destinations.",
  "Barracuda VPN": "Barracuda VPN tunnel ownership may conflict with GSA routing. Configure Barracuda Network Access Client with split-tunnel exclusions for Microsoft 365 and Entra ID prefixes, or disconnect Barracuda VPN on devices using GSA tunnels.",
  "WatchGuard Mobile VPN": "WatchGuard Mobile VPN SSL/IPsec client may conflict with GSA route ownership. Configure split-tunnel exclusions for Microsoft 365 and Entra ID destinations, or disconnect the WatchGuard VPN while GSA tunnels are active.",
  "Array Networks VPN": "Array Networks SSL VPN may overlap with GSA private access routing. Configure the Array VPN resource policy to exclude destinations handled by GSA, or disable the Array VPN client on devices where GSA manages private application access.",
  "Aruba VIA": "Aruba VIA installs virtual adapters and routing rules that may conflict with GSA. Configure Aruba VIA split-tunnel policy to exclude Microsoft 365, Entra ID, and GSA-tunneled destinations.",
  "Digital Guardian": "Digital Guardian DLP uses kernel-level WFP filtering that may interfere with GSA traffic processing. Add GlobalSecureAccessDriver and its associated services to the Digital Guardian exclusion policy, or disable the network interception module on GSA-managed devices.",
  "Proofpoint Endpoint DLP": "Proofpoint Endpoint DLP monitors network traffic for data loss prevention and may affect GSA tunnel classification. Add GSA executables and drivers to the Proofpoint exclusion list to prevent interference with tunnel traffic.",
  "CoSoSys Endpoint Protector": "CoSoSys Endpoint Protector uses network controls that may conditionally conflict with GSA. Review network monitoring policies in the Endpoint Protector console and add GSA drivers and services to the exclusion list.",
  "ManageEngine DataSecurity Plus": "ManageEngine DataSecurity Plus is primarily a monitoring tool with low conflict risk. Inventory its network inspection policies and ensure GlobalSecureAccessDriver is excluded from active inspection rules.",
  "Menlo Security": "Menlo Security isolation and SWG functions may affect GSA traffic steering. Configure Menlo Security policy to bypass GSA-tunneled traffic (Microsoft 365, Entra ID, Private Access destinations), or disable the Menlo Security connector on GSA-managed devices.",
  "Ericom Shield": "Ericom Shield browser isolation may overlap with GSA internet access routing. Configure Ericom Shield to exclude Microsoft 365 and Entra ID traffic from isolation, ensuring GSA handles those flows.",
  "ZeroTier": "ZeroTier injects virtual network adapters and custom routes that may conflict with GSA traffic redirection. Configure ZeroTier network rules to exclude Microsoft 365, Entra ID, and Private Access prefixes, or leave those routes to be handled exclusively by GSA.",
  "NetBird": "NetBird uses the Wintun kernel driver for its mesh VPN tunnel, which operates at the same WFP layers as GSA. Configure NetBird split-tunnel routes to exclude Microsoft 365, Entra ID, and GSA-tunneled destinations.",
  "Headscale": "Headscale-based Tailscale deployments use the Wintun adapter and are generally low risk. If GSA connectivity issues arise, verify that Wintun driver registration does not conflict with GSA and configure split-tunnel to exclude GSA-managed destinations.",
  "Cato Networks": "Cato SASE client owns the full network stack (DNS, SWG, ZTNA, VPN). In the Cato Management Application, configure split-tunnel or bypass rules to exclude Microsoft 365, Entra ID, and GSA-tunneled destinations. On devices where GSA handles secure access, disable the Cato Client or set it to monitor-only mode.",
  "VMware Workspace ONE Tunnel": "Workspace ONE Tunnel provides per-app VPN and enterprise application access. In the Workspace ONE UEM console, configure traffic rules to exclude Microsoft 365, Entra ID, and GSA-tunneled destinations from the tunnel. On devices where GSA handles private access, disable the Tunnel profile.",
  "BeyondTrust Secure Remote Access": "BeyondTrust (formerly Bomgar) remote access may install network drivers. Verify that BeyondTrust network components are not intercepting GSA tunnel traffic. Coordinate with your BeyondTrust admin to add GSA services to the exclusion list.",
  "NordVPN": "NordVPN uses NordLynx (WireGuard) and TAP adapters. Disconnect NordVPN before establishing GSA tunnels, or configure NordVPN split-tunneling to exclude Microsoft 365, Entra ID, and GSA-managed destinations.",
  "ExpressVPN": "ExpressVPN owns DNS and routing tables while active. Disconnect ExpressVPN before using GSA tunnels, or configure split-tunneling to exclude Microsoft 365, Entra ID, and Private Access destinations.",
  "Surfshark": "Surfshark uses WireGuard tunneling and may conflict with GSA route ownership. Disconnect Surfshark or configure its split-tunneling (Bypasser) to exclude Microsoft 365 and Entra ID traffic.",
  "Proton VPN": "Proton VPN intercepts DNS and owns routes while active. Disconnect Proton VPN before using GSA tunnels, or configure Proton VPN split-tunneling to exclude Microsoft 365, Entra ID, and GSA-managed destinations.",
  "Mullvad VPN": "Mullvad VPN uses WireGuard and may conflict with GSA traffic steering. Disconnect Mullvad before establishing GSA tunnels, or use Mullvad's split-tunneling to exclude GSA-managed traffic.",
  "Cita VPN": "Cita VPN creates encrypted tunnels that may conflict with GSA routing. Disconnect Cita VPN before using GSA tunnels to avoid route ownership conflicts.",
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
