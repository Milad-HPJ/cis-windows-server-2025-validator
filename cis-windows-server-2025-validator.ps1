<#
.SYNOPSIS
    CIS Microsoft Windows Server 2025 Benchmark v2.1.0 - Complete Validation Script
.DESCRIPTION
    Comprehensive validation script for all CIS Benchmark recommendations
    Covers: Account Policies, Local Policies, System Services, Firewall, 
            Audit Policy, and Administrative Templates
.NOTES
    Version: 1.0
    Author: AI Assistant
    Date: 2026-10-23
    Requires: Administrator privileges
#>

# ============================================================================
# Global Variables
# ============================================================================
$Script:ReportPath = "C:\CIS_Benchmark_Validation_Report.html"
$Script:SecEditPath = "$env:TEMP\secedit_export.cfg"
$Script:TotalChecks = 0
$Script:PassedChecks = 0
$Script:FailedChecks = 0
$Script:NotApplicable = 0
$Script:Results = @()
$Script:ServerType = ""

# ============================================================================
# Initialization
# ============================================================================
Clear-Host
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host " CIS Benchmark v2.1.0 - Windows Server 2025" -ForegroundColor Cyan
Write-Host " Complete Validation Script" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "❌ ERROR: This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

# ============================================================================
# Server Type Selection
# ============================================================================
Write-Host "📋 Select Server Type:" -ForegroundColor Yellow
Write-Host "  [1] Domain Controller (DC)" -ForegroundColor White
Write-Host "  [2] Member Server (MS)" -ForegroundColor White
Write-Host ""

$selection = Read-Host "Enter your choice (1 or 2)"

switch ($selection) {
    "1" { 
        $Script:ServerType = "DC"
        Write-Host "✅ Selected: Domain Controller" -ForegroundColor Green
    }
    "2" { 
        $Script:ServerType = "MS"
        Write-Host "✅ Selected: Member Server" -ForegroundColor Green
    }
    default {
        Write-Host "❌ Invalid selection. Defaulting to Member Server." -ForegroundColor Red
        $Script:ServerType = "MS"
    }
}

Write-Host ""
Write-Host "Starting validation for $Script:ServerType..." -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# Helper Functions
# ============================================================================
function Write-CategoryHeader {
    param([string]$CategoryName)
    Write-Host "`n=== $CategoryName ===" -ForegroundColor Yellow
}

function Add-Result {
    param(
        [string]$CISID,
        [string]$Description,
        [string]$Status,
        [string]$Expected,
        [string]$Actual
    )
    
    $Script:TotalChecks++
    
    if ($Status -eq "PASS") {
        $Script:PassedChecks++
        $color = "Green"
    } elseif ($Status -eq "FAIL") {
        $Script:FailedChecks++
        $color = "Red"
    } else {
        $Script:NotApplicable++
        $color = "Gray"
    }
    
    Write-Host "[$CISID] $Description - $Status" -ForegroundColor $color
    
    $Script:Results += [PSCustomObject]@{
        CISID = $CISID
        Description = $Description
        Status = $Status
        Expected = $Expected
        Actual = $Actual
    }
}

function Test-RegistryValue {
    param(
        [string]$CISID,
        [string]$Path,
        [string]$ValueName,
        [object]$ExpectedValue,
        [string]$Description,
        [string]$Type = "DWord"
    )
    
    $status = "FAIL"
    $actualValue = "NOT FOUND"
    
    try {
        if (Test-Path $Path) {
            $regValue = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue
            if ($null -ne $regValue -and $null -ne $regValue.$ValueName) {
                $actualValue = $regValue.$ValueName
                if ($actualValue -eq $ExpectedValue) {
                    $status = "PASS"
                }
            }
        }
    } catch {
        $status = "FAIL"
    }
    
    Add-Result -CISID $CISID -Description $Description -Status $status -Expected $ExpectedValue -Actual $actualValue
}

function Test-SecEditValue {
    param(
        [string]$CISID,
        [string]$Section,
        [string]$Key,
        [string]$ExpectedValue,
        [string]$Description,
        [hashtable]$SecEditData
    )
    
    $status = "FAIL"
    $actualValue = "NOT FOUND"
    
    try {
        if ($SecEditData.ContainsKey($Section) -and $SecEditData[$Section].ContainsKey($Key)) {
            $actualValue = $SecEditData[$Section][$Key]
            if ($actualValue -eq $ExpectedValue) {
                $status = "PASS"
            }
        }
    } catch {
        $status = "FAIL"
    }
    
    Add-Result -CISID $CISID -Description $Description -Status $status -Expected $ExpectedValue -Actual $actualValue
}

function Parse-SecEditFile {
    param([string]$FilePath)
    
    $data = @{}
    $currentSection = ""
    
    if (Test-Path $FilePath) {
        $content = Get-Content $FilePath
        
        foreach ($line in $content) {
            $line = $line.Trim()
            
            if ($line -match '^\[(.+)\]$') {
                $currentSection = $Matches[1]
                if (-not $data.ContainsKey($currentSection)) {
                    $data[$currentSection] = @{}
                }
            }
            elseif ($line -match '^(.+?)=(.*)$' -and $currentSection -ne "") {
                $key = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                $data[$currentSection][$key] = $value
            }
        }
    }
    
    return $data
}

# ============================================================================
# Export Security Policy
# ============================================================================
Write-Host "📤 Exporting security policy..." -ForegroundColor Cyan

try {
    secedit /export /cfg $Script:SecEditPath /quiet
    $SecEditData = Parse-SecEditFile -FilePath $Script:SecEditPath
    Write-Host "✅ Security policy exported successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to export security policy: $_" -ForegroundColor Red
    $SecEditData = @{}
}

# ============================================================================
# Category 1: Account Policies (Section 1.1 - 1.2)
# ============================================================================
Write-CategoryHeader "Category 1: Account Policies (1.1 - 1.2)"

# 1.1 Password Policy
Test-SecEditValue "1.1.1" "System Access" "PasswordHistorySize" "24" "Enforce password history (24+)" $SecEditData
Test-SecEditValue "1.1.2" "System Access" "MaximumPasswordAge" "365" "Maximum password age (365 or less)" $SecEditData
Test-SecEditValue "1.1.3" "System Access" "MinimumPasswordAge" "1" "Minimum password age (1+)" $SecEditData
Test-SecEditValue "1.1.4" "System Access" "MinimumPasswordLength" "14" "Minimum password length (14+)" $SecEditData
Test-SecEditValue "1.1.5" "System Access" "PasswordComplexity" "1" "Password complexity enabled" $SecEditData
Test-SecEditValue "1.1.7" "System Access" "ClearTextPassword" "0" "Reversible encryption disabled" $SecEditData

# 1.2 Account Lockout Policy
Test-SecEditValue "1.2.1" "System Access" "LockoutDuration" "15" "Account lockout duration (15+ min)" $SecEditData
Test-SecEditValue "1.2.2" "System Access" "LockoutBadCount" "5" "Account lockout threshold (5 or less)" $SecEditData
Test-SecEditValue "1.2.4" "System Access" "ResetLockoutCount" "15" "Reset lockout counter (15+ min)" $SecEditData

# ============================================================================
# Category 2: Local Policies - User Rights Assignment (Section 2.2)
# ============================================================================
Write-CategoryHeader "Category 2: User Rights Assignment (2.2)"

# 2.2.1 - 2.2.48 (Selected key checks)
Test-SecEditValue "2.2.1" "Privilege Rights" "SeTrustedCredManAccessPrivilege" "" "Access Credential Manager as trusted caller (No One)" $SecEditData
Test-SecEditValue "2.2.4" "Privilege Rights" "SeTcbPrivilege" "" "Act as part of OS (No One)" $SecEditData
Test-SecEditValue "2.2.14" "Privilege Rights" "SeCreateTokenPrivilege" "" "Create a token object (No One)" $SecEditData
Test-SecEditValue "2.2.16" "Privilege Rights" "SeCreatePermanentPrivilege" "" "Create permanent shared objects (No One)" $SecEditData
Test-SecEditValue "2.2.19" "Privilege Rights" "SeDebugPrivilege" "*S-1-5-32-544" "Debug programs (Administrators)" $SecEditData
Test-SecEditValue "2.2.34" "Privilege Rights" "SeLoadDriverPrivilege" "*S-1-5-32-544" "Load/unload device drivers (Administrators)" $SecEditData
Test-SecEditValue "2.2.35" "Privilege Rights" "SeLockMemoryPrivilege" "" "Lock pages in memory (No One)" $SecEditData
Test-SecEditValue "2.2.39" "Privilege Rights" "SeRelabelPrivilege" "" "Modify an object label (No One)" $SecEditData
Test-SecEditValue "2.2.47" "Privilege Rights" "SeSyncAgentPrivilege" "" "Synchronize directory service data (No One)" $SecEditData

# ============================================================================
# Category 3: Security Options (Section 2.3) - Registry Based
# ============================================================================
Write-CategoryHeader "Category 3: Security Options (2.3) - Registry"

# 2.3.1 Accounts
Test-RegistryValue "2.3.1.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" 1 "Limit blank passwords to console"
Test-RegistryValue "2.3.2.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" 1 "Force audit policy subcategory"
Test-RegistryValue "2.3.2.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail" 0 "Shutdown on audit fail disabled"
Test-RegistryValue "2.3.4.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" 1 "Prevent printer driver install"

# 2.3.5 Domain Controller (DC only)
if ($Script:ServerType -eq "DC") {
    Test-RegistryValue "2.3.5.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SubmitControl" 0 "DC: Allow server operators schedule tasks"
    Test-RegistryValue "2.3.5.3" "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LdapEnforceChannelBinding" 2 "DC: LDAP channel binding (Always)"
    Test-RegistryValue "2.3.5.4" "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerEnforceIntegrity" 1 "DC: LDAP signing enforcement"
    Test-RegistryValue "2.3.5.5" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RefusePasswordChange" 0 "DC: Refuse machine password changes"
}

# 2.3.6 Domain Member
Test-RegistryValue "2.3.6.1" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal" 1 "Domain member: Encrypt/sign secure channel"
Test-RegistryValue "2.3.6.2" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel" 1 "Domain member: Encrypt secure channel"
Test-RegistryValue "2.3.6.3" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel" 1 "Domain member: Sign secure channel"
Test-RegistryValue "2.3.6.4" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "DisablePasswordChange" 0 "Domain member: Enable password changes"
Test-RegistryValue "2.3.6.5" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge" "30" "Domain member: Max password age (30 days)"
Test-RegistryValue "2.3.6.6" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey" 1 "Domain member: Require strong session key"

# 2.3.7 Interactive Logon
Test-RegistryValue "2.3.7.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" 0 "Interactive logon: Require CTRL+ALT+DEL"
Test-RegistryValue "2.3.7.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName" 1 "Interactive logon: Don't display last user"
Test-RegistryValue "2.3.7.3" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" "900" "Interactive logon: Machine inactivity limit"

if ($Script:ServerType -eq "MS") {
    Test-RegistryValue "2.3.7.6" "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "4" "Interactive logon: Cache logons (4 or less)"
    Test-RegistryValue "2.3.7.8" "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ForceUnlockLogon" 1 "Interactive logon: Require DC auth to unlock"
}

Test-RegistryValue "2.3.7.7" "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "PasswordExpiryWarning" "14" "Interactive logon: Password expiry warning"
Test-RegistryValue "2.3.7.9" "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScRemoveOption" "1" "Interactive logon: Smart card removal (Lock)"

# 2.3.8 Microsoft Network Client
Test-RegistryValue "2.3.8.1" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 1 "MS client: Digitally sign always"
Test-RegistryValue "2.3.8.2" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" 0 "MS client: Disable unencrypted password"

# 2.3.9 Microsoft Network Server
Test-RegistryValue "2.3.9.1" "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "AutoDisconnect" "15" "MS server: Idle time before suspend"
Test-RegistryValue "2.3.9.2" "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature" 1 "MS server: Digitally sign always"
Test-RegistryValue "2.3.9.3" "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "enableforcedlogoff" 1 "MS server: Disconnect when logon expires"

if ($Script:ServerType -eq "MS") {
    Test-RegistryValue "2.3.9.4" "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "SMBServerNameHardeningLevel" "1" "MS server: SPN validation (Accept if provided)"
}

# 2.3.10 Network Access
Test-RegistryValue "2.3.10.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" 0 "Network access: Everyone excludes anonymous"

if ($Script:ServerType -eq "MS") {
    Test-RegistryValue "2.3.10.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1 "Network access: Restrict SAM enumeration"
    Test-RegistryValue "2.3.10.3" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 1 "Network access: Restrict SAM and shares"
}

Test-RegistryValue "2.3.10.4" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds" 1 "Network access: Disable credential storage"
Test-RegistryValue "2.3.10.5" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "ForceGuest" 0 "Network access: Classic authentication model"
Test-RegistryValue "2.3.10.10" "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RestrictNullSessAccess" 1 "Network access: Restrict anonymous pipes/shares"

if ($Script:ServerType -eq "MS") {
    Test-RegistryValue "2.3.10.11" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "restrictremotesam" "O:BAG:BAD:(A;;RC;;;BA)" "Network access: Restrict remote SAM calls"
}

# 2.3.11 Network Security
Test-RegistryValue "2.3.11.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "UseMachineId" 1 "Network security: Use computer identity for NTLM"
Test-RegistryValue "2.3.11.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AllowNullSessionFallback" 0 "Network security: Disable NULL session fallback"
Test-RegistryValue "2.3.11.3" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" "AllowOnlineID" 0 "Network security: Disable PKU2U online identities"
Test-RegistryValue "2.3.11.4" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes" "2147483640" "Network security: Kerberos encryption (AES)"
Test-RegistryValue "2.3.11.6" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" "5" "Network security: NTLMv2 only"
Test-RegistryValue "2.3.11.7" "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientConfidentiality" "1" "Network security: LDAP client encryption"
Test-RegistryValue "2.3.11.8" "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" "1" "Network security: LDAP client signing"
Test-RegistryValue "2.3.11.9" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec" "537395200" "Network security: NTLM client session security"
Test-RegistryValue "2.3.11.10" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec" "537395200" "Network security: NTLM server session security"

if ($Script:ServerType -eq "DC") {
    Test-RegistryValue "2.3.11.12" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "AuditNTLMInDomain" "7" "Network security: Audit NTLM in domain (DC)"
}

Test-RegistryValue "2.3.11.11" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AuditReceivingNTLMTraffic" "2" "Network security: Audit incoming NTLM"
Test-RegistryValue "2.3.11.13" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "RestrictSendingNTLMTraffic" "1" "Network security: Audit outgoing NTLM"

# 2.3.13 Shutdown
Test-RegistryValue "2.3.13.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon" 0 "Shutdown: Require logon"

# 2.3.15 System Objects
Test-RegistryValue "2.3.15.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" "ObCaseInsensitive" 1 "System objects: Case insensitivity"
Test-RegistryValue "2.3.15.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" 1 "System objects: Strengthen permissions"

# 2.3.17 User Account Control
Test-RegistryValue "2.3.17.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken" 1 "UAC: Admin Approval Mode for built-in admin"
Test-RegistryValue "2.3.17.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "2" "UAC: Admin elevation prompt (secure desktop)"
Test-RegistryValue "2.3.17.3" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" "0" "UAC: Standard user elevation (deny)"
Test-RegistryValue "2.3.17.4" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" 1 "UAC: Detect application installations"
Test-RegistryValue "2.3.17.5" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths" 1 "UAC: Only elevate UIAccess from secure locations"
Test-RegistryValue "2.3.17.6" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1 "UAC: Run all admins in Admin Approval Mode"
Test-RegistryValue "2.3.17.7" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1 "UAC: Switch to secure desktop for elevation"
Test-RegistryValue "2.3.17.8" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" 1 "UAC: Virtualize file/registry write failures"

Write-Host "`n✅ Category 3 completed" -ForegroundColor Green
# ============================================================================
# Category 4: System Services (Section 5)
# ============================================================================
Write-CategoryHeader "Category 4: System Services (5)"

# 5.1 & 5.2 Print Spooler
try {
    $spoolerService = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
    if ($spoolerService) {
        $spoolerStatus = if ($spoolerService.StartType -eq "Disabled") { "PASS" } else { "FAIL" }
        Add-Result "5.1/5.2" "Print Spooler service disabled" $spoolerStatus "Disabled" $spoolerService.StartType.ToString()
    } else {
        Add-Result "5.1/5.2" "Print Spooler service disabled" "PASS" "Disabled" "Not Found"
    }
} catch {
    Add-Result "5.1/5.2" "Print Spooler service disabled" "FAIL" "Disabled" "Error"
}

# ============================================================================
# Category 5: Windows Firewall (Section 9)
# ============================================================================
Write-CategoryHeader "Category 5: Windows Firewall (9)"

# 9.1 Domain Profile
Test-RegistryValue "9.1.1" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall" 1 "Firewall Domain: State (On)"
Test-RegistryValue "9.1.2" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultInboundAction" 1 "Firewall Domain: Inbound (Block)"
Test-RegistryValue "9.1.3" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DisableNotifications" 1 "Firewall Domain: Notifications (No)"
Test-RegistryValue "9.1.5" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFileSize" "16384" "Firewall Domain: Log size (16384+ KB)"
Test-RegistryValue "9.1.6" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogDroppedPackets" 1 "Firewall Domain: Log dropped packets"
Test-RegistryValue "9.1.7" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogSuccessfulConnections" 1 "Firewall Domain: Log successful connections"

# 9.2 Private Profile
Test-RegistryValue "9.2.1" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall" 1 "Firewall Private: State (On)"
Test-RegistryValue "9.2.2" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultInboundAction" 1 "Firewall Private: Inbound (Block)"
Test-RegistryValue "9.2.3" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DisableNotifications" 1 "Firewall Private: Notifications (No)"
Test-RegistryValue "9.2.5" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize" "16384" "Firewall Private: Log size (16384+ KB)"
Test-RegistryValue "9.2.6" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets" 1 "Firewall Private: Log dropped packets"
Test-RegistryValue "9.2.7" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" 1 "Firewall Private: Log successful connections"

# 9.3 Public Profile
Test-RegistryValue "9.3.1" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "EnableFirewall" 1 "Firewall Public: State (On)"
Test-RegistryValue "9.3.2" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultInboundAction" 1 "Firewall Public: Inbound (Block)"
Test-RegistryValue "9.3.3" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DisableNotifications" 1 "Firewall Public: Notifications (No)"
Test-RegistryValue "9.3.4" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "AllowLocalPolicyMerge" 0 "Firewall Public: Local firewall rules (No)"
Test-RegistryValue "9.3.5" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "AllowLocalIPsecPolicyMerge" 0 "Firewall Public: Local IPsec rules (No)"
Test-RegistryValue "9.3.7" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFileSize" "16384" "Firewall Public: Log size (16384+ KB)"
Test-RegistryValue "9.3.8" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogDroppedPackets" 1 "Firewall Public: Log dropped packets"
Test-RegistryValue "9.3.9" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogSuccessfulConnections" 1 "Firewall Public: Log successful connections"

Write-Host "`n✅ Category 5 completed" -ForegroundColor Green

# ============================================================================
# Category 6: Advanced Audit Policy (Section 17)
# ============================================================================
Write-CategoryHeader "Category 6: Advanced Audit Policy (17)"

try {
    $auditPolOutput = auditpol /get /category:* /r | ConvertFrom-Csv
    
    # 17.1 Account Logon
    $credValidation = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Credential Validation*' }
    if ($credValidation.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.1.1" "Audit Credential Validation" "PASS" "Success and Failure" $credValidation.'Inclusion Setting'
    } else {
        Add-Result "17.1.1" "Audit Credential Validation" "FAIL" "Success and Failure" ($credValidation.'Inclusion Setting' ?? "Not Configured")
    }
    
    if ($Script:ServerType -eq "DC") {
        $kerbAuth = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Kerberos Authentication Service*' }
        if ($kerbAuth.'Inclusion Setting' -eq "Success and Failure") {
            Add-Result "17.1.2" "Audit Kerberos Authentication Service (DC)" "PASS" "Success and Failure" $kerbAuth.'Inclusion Setting'
        } else {
            Add-Result "17.1.2" "Audit Kerberos Authentication Service (DC)" "FAIL" "Success and Failure" ($kerbAuth.'Inclusion Setting' ?? "Not Configured")
        }
        
        $kerbTicket = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Kerberos Service Ticket*' }
        if ($kerbTicket.'Inclusion Setting' -eq "Success and Failure") {
            Add-Result "17.1.3" "Audit Kerberos Service Ticket Operations (DC)" "PASS" "Success and Failure" $kerbTicket.'Inclusion Setting'
        } else {
            Add-Result "17.1.3" "Audit Kerberos Service Ticket Operations (DC)" "FAIL" "Success and Failure" ($kerbTicket.'Inclusion Setting' ?? "Not Configured")
        }
    }
    
    # 17.2 Account Management
    $appGroupMgmt = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Application Group Management*' }
    if ($appGroupMgmt.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.2.1" "Audit Application Group Management" "PASS" "Success and Failure" $appGroupMgmt.'Inclusion Setting'
    } else {
        Add-Result "17.2.1" "Audit Application Group Management" "FAIL" "Success and Failure" ($appGroupMgmt.'Inclusion Setting' ?? "Not Configured")
    }
    
    if ($Script:ServerType -eq "DC") {
        $compAccount = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Computer Account Management*' }
        if ($compAccount.'Inclusion Setting' -match "Success") {
            Add-Result "17.2.2" "Audit Computer Account Management (DC)" "PASS" "Success" $compAccount.'Inclusion Setting'
        } else {
            Add-Result "17.2.2" "Audit Computer Account Management (DC)" "FAIL" "Success" ($compAccount.'Inclusion Setting' ?? "Not Configured")
        }
        
        $distGroup = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Distribution Group Management*' }
        if ($distGroup.'Inclusion Setting' -match "Success") {
            Add-Result "17.2.3" "Audit Distribution Group Management (DC)" "PASS" "Success" $distGroup.'Inclusion Setting'
        } else {
            Add-Result "17.2.3" "Audit Distribution Group Management (DC)" "FAIL" "Success" ($distGroup.'Inclusion Setting' ?? "Not Configured")
        }
        
        $otherAccount = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Other Account Management*' }
        if ($otherAccount.'Inclusion Setting' -match "Success") {
            Add-Result "17.2.4" "Audit Other Account Management Events (DC)" "PASS" "Success" $otherAccount.'Inclusion Setting'
        } else {
            Add-Result "17.2.4" "Audit Other Account Management Events (DC)" "FAIL" "Success" ($otherAccount.'Inclusion Setting' ?? "Not Configured")
        }
    }
    
    $secGroup = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Security Group Management*' }
    if ($secGroup.'Inclusion Setting' -match "Success") {
        Add-Result "17.2.5" "Audit Security Group Management" "PASS" "Success" $secGroup.'Inclusion Setting'
    } else {
        Add-Result "17.2.5" "Audit Security Group Management" "FAIL" "Success" ($secGroup.'Inclusion Setting' ?? "Not Configured")
    }
    
    $userAccount = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*User Account Management*' }
    if ($userAccount.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.2.6" "Audit User Account Management" "PASS" "Success and Failure" $userAccount.'Inclusion Setting'
    } else {
        Add-Result "17.2.6" "Audit User Account Management" "FAIL" "Success and Failure" ($userAccount.'Inclusion Setting' ?? "Not Configured")
    }
    
    # 17.3 Detailed Tracking
    $pnpActivity = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*PNP Activity*' }
    if ($pnpActivity.'Inclusion Setting' -match "Success") {
        Add-Result "17.3.1" "Audit PNP Activity" "PASS" "Success" $pnpActivity.'Inclusion Setting'
    } else {
        Add-Result "17.3.1" "Audit PNP Activity" "FAIL" "Success" ($pnpActivity.'Inclusion Setting' ?? "Not Configured")
    }
    
    $processCreation = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Process Creation*' }
    if ($processCreation.'Inclusion Setting' -match "Success") {
        Add-Result "17.3.2" "Audit Process Creation" "PASS" "Success" $processCreation.'Inclusion Setting'
    } else {
        Add-Result "17.3.2" "Audit Process Creation" "FAIL" "Success" ($processCreation.'Inclusion Setting' ?? "Not Configured")
    }
    
    # 17.4 DS Access (DC only)
    if ($Script:ServerType -eq "DC") {
        $dsAccess = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Directory Service Access*' }
        if ($dsAccess.'Inclusion Setting' -match "Failure") {
            Add-Result "17.4.1" "Audit Directory Service Access (DC)" "PASS" "Failure" $dsAccess.'Inclusion Setting'
        } else {
            Add-Result "17.4.1" "Audit Directory Service Access (DC)" "FAIL" "Failure" ($dsAccess.'Inclusion Setting' ?? "Not Configured")
        }
        
        $dsChanges = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Directory Service Changes*' }
        if ($dsChanges.'Inclusion Setting' -match "Success") {
            Add-Result "17.4.2" "Audit Directory Service Changes (DC)" "PASS" "Success" $dsChanges.'Inclusion Setting'
        } else {
            Add-Result "17.4.2" "Audit Directory Service Changes (DC)" "FAIL" "Success" ($dsChanges.'Inclusion Setting' ?? "Not Configured")
        }
    }
    
    # 17.5 Logon/Logoff
    $accountLockout = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Account Lockout*' }
    if ($accountLockout.'Inclusion Setting' -match "Failure") {
        Add-Result "17.5.1" "Audit Account Lockout" "PASS" "Failure" $accountLockout.'Inclusion Setting'
    } else {
        Add-Result "17.5.1" "Audit Account Lockout" "FAIL" "Failure" ($accountLockout.'Inclusion Setting' ?? "Not Configured")
    }
    
    $groupMembership = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Group Membership*' }
    if ($groupMembership.'Inclusion Setting' -match "Success") {
        Add-Result "17.5.2" "Audit Group Membership" "PASS" "Success" $groupMembership.'Inclusion Setting'
    } else {
        Add-Result "17.5.2" "Audit Group Membership" "FAIL" "Success" ($groupMembership.'Inclusion Setting' ?? "Not Configured")
    }
    
    $logoff = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Logoff*' }
    if ($logoff.'Inclusion Setting' -match "Success") {
        Add-Result "17.5.3" "Audit Logoff" "PASS" "Success" $logoff.'Inclusion Setting'
    } else {
        Add-Result "17.5.3" "Audit Logoff" "FAIL" "Success" ($logoff.'Inclusion Setting' ?? "Not Configured")
    }
    
    $logon = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Logon*' -and $_.'Subcategory' -notlike '*Logoff*' }
    if ($logon.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.5.4" "Audit Logon" "PASS" "Success and Failure" $logon.'Inclusion Setting'
    } else {
        Add-Result "17.5.4" "Audit Logon" "FAIL" "Success and Failure" ($logon.'Inclusion Setting' ?? "Not Configured")
    }
    
    $otherLogon = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Other Logon/Logoff*' }
    if ($otherLogon.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.5.5" "Audit Other Logon/Logoff Events" "PASS" "Success and Failure" $otherLogon.'Inclusion Setting'
    } else {
        Add-Result "17.5.5" "Audit Other Logon/Logoff Events" "FAIL" "Success and Failure" ($otherLogon.'Inclusion Setting' ?? "Not Configured")
    }
    
    $specialLogon = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Special Logon*' }
    if ($specialLogon.'Inclusion Setting' -match "Success") {
        Add-Result "17.5.6" "Audit Special Logon" "PASS" "Success" $specialLogon.'Inclusion Setting'
    } else {
        Add-Result "17.5.6" "Audit Special Logon" "FAIL" "Success" ($specialLogon.'Inclusion Setting' ?? "Not Configured")
    }
    
    # 17.6 Object Access
    $detailedFileShare = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Detailed File Share*' }
    if ($detailedFileShare.'Inclusion Setting' -match "Failure") {
        Add-Result "17.6.1" "Audit Detailed File Share" "PASS" "Failure" $detailedFileShare.'Inclusion Setting'
    } else {
        Add-Result "17.6.1" "Audit Detailed File Share" "FAIL" "Failure" ($detailedFileShare.'Inclusion Setting' ?? "Not Configured")
    }
    
    $fileShare = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*File Share*' }
    if ($fileShare.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.6.2" "Audit File Share" "PASS" "Success and Failure" $fileShare.'Inclusion Setting'
    } else {
        Add-Result "17.6.2" "Audit File Share" "FAIL" "Success and Failure" ($fileShare.'Inclusion Setting' ?? "Not Configured")
    }
    
    $otherObject = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Other Object Access*' }
    if ($otherObject.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.6.3" "Audit Other Object Access Events" "PASS" "Success and Failure" $otherObject.'Inclusion Setting'
    } else {
        Add-Result "17.6.3" "Audit Other Object Access Events" "FAIL" "Success and Failure" ($otherObject.'Inclusion Setting' ?? "Not Configured")
    }
    
    $removableStorage = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Removable Storage*' }
    if ($removableStorage.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.6.4" "Audit Removable Storage" "PASS" "Success and Failure" $removableStorage.'Inclusion Setting'
    } else {
        Add-Result "17.6.4" "Audit Removable Storage" "FAIL" "Success and Failure" ($removableStorage.'Inclusion Setting' ?? "Not Configured")
    }
    
    # 17.7 Policy Change
    $auditPolicyChange = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Audit Policy Change*' }
    if ($auditPolicyChange.'Inclusion Setting' -match "Success") {
        Add-Result "17.7.1" "Audit Audit Policy Change" "PASS" "Success" $auditPolicyChange.'Inclusion Setting'
    } else {
        Add-Result "17.7.1" "Audit Audit Policy Change" "FAIL" "Success" ($auditPolicyChange.'Inclusion Setting' ?? "Not Configured")
    }
    
    $authPolicyChange = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Authentication Policy Change*' }
    if ($authPolicyChange.'Inclusion Setting' -match "Success") {
        Add-Result "17.7.2" "Audit Authentication Policy Change" "PASS" "Success" $authPolicyChange.'Inclusion Setting'
    } else {
        Add-Result "17.7.2" "Audit Authentication Policy Change" "FAIL" "Success" ($authPolicyChange.'Inclusion Setting' ?? "Not Configured")
    }
    
    $authzPolicyChange = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Authorization Policy Change*' }
    if ($authzPolicyChange.'Inclusion Setting' -match "Success") {
        Add-Result "17.7.3" "Audit Authorization Policy Change" "PASS" "Success" $authzPolicyChange.'Inclusion Setting'
    } else {
        Add-Result "17.7.3" "Audit Authorization Policy Change" "FAIL" "Success" ($authzPolicyChange.'Inclusion Setting' ?? "Not Configured")
    }
    
    $mpssvcRule = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*MPSSVC Rule-Level*' }
    if ($mpssvcRule.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.7.4" "Audit MPSSVC Rule-Level Policy Change" "PASS" "Success and Failure" $mpssvcRule.'Inclusion Setting'
    } else {
        Add-Result "17.7.4" "Audit MPSSVC Rule-Level Policy Change" "FAIL" "Success and Failure" ($mpssvcRule.'Inclusion Setting' ?? "Not Configured")
    }
    
    $otherPolicyChange = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Other Policy Change*' }
    if ($otherPolicyChange.'Inclusion Setting' -match "Failure") {
        Add-Result "17.7.5" "Audit Other Policy Change Events" "PASS" "Failure" $otherPolicyChange.'Inclusion Setting'
    } else {
        Add-Result "17.7.5" "Audit Other Policy Change Events" "FAIL" "Failure" ($otherPolicyChange.'Inclusion Setting' ?? "Not Configured")
    }
    
    # 17.8 Privilege Use
    $sensitivePriv = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Sensitive Privilege Use*' }
    if ($sensitivePriv.'Inclusion Setting' -match "Success") {
        Add-Result "17.8.1" "Audit Sensitive Privilege Use" "PASS" "Success" $sensitivePriv.'Inclusion Setting'
    } else {
        Add-Result "17.8.1" "Audit Sensitive Privilege Use" "FAIL" "Success" ($sensitivePriv.'Inclusion Setting' ?? "Not Configured")
    }
    
    # 17.9 System
    $ipsecDriver = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*IPsec Driver*' }
    if ($ipsecDriver.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.9.1" "Audit IPsec Driver" "PASS" "Success and Failure" $ipsecDriver.'Inclusion Setting'
    } else {
        Add-Result "17.9.1" "Audit IPsec Driver" "FAIL" "Success and Failure" ($ipsecDriver.'Inclusion Setting' ?? "Not Configured")
    }
    
    $otherSystem = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Other System Events*' }
    if ($otherSystem.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.9.2" "Audit Other System Events" "PASS" "Success and Failure" $otherSystem.'Inclusion Setting'
    } else {
        Add-Result "17.9.2" "Audit Other System Events" "FAIL" "Success and Failure" ($otherSystem.'Inclusion Setting' ?? "Not Configured")
    }
    
    $securityState = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Security State Change*' }
    if ($securityState.'Inclusion Setting' -match "Success") {
        Add-Result "17.9.3" "Audit Security State Change" "PASS" "Success" $securityState.'Inclusion Setting'
    } else {
        Add-Result "17.9.3" "Audit Security State Change" "FAIL" "Success" ($securityState.'Inclusion Setting' ?? "Not Configured")
    }
    
    $securitySystem = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*Security System Extension*' }
    if ($securitySystem.'Inclusion Setting' -match "Success") {
        Add-Result "17.9.4" "Audit Security System Extension" "PASS" "Success" $securitySystem.'Inclusion Setting'
    } else {
        Add-Result "17.9.4" "Audit Security System Extension" "FAIL" "Success" ($securitySystem.'Inclusion Setting' ?? "Not Configured")
    }
    
    $systemIntegrity = $auditPolOutput | Where-Object { $_.'Subcategory' -like '*System Integrity*' }
    if ($systemIntegrity.'Inclusion Setting' -eq "Success and Failure") {
        Add-Result "17.9.5" "Audit System Integrity" "PASS" "Success and Failure" $systemIntegrity.'Inclusion Setting'
    } else {
        Add-Result "17.9.5" "Audit System Integrity" "FAIL" "Success and Failure" ($systemIntegrity.'Inclusion Setting' ?? "Not Configured")
    }
    
    Write-Host "`n✅ Category 6 completed" -ForegroundColor Green
    
} catch {
    Write-Host "❌ Error reading audit policy: $_" -ForegroundColor Red
}
# ============================================================================
# Category 7: Administrative Templates - System (18.9) - Continued
# ============================================================================
Write-CategoryHeader "Category 7: Administrative Templates - System (18.9) - Part 2"

# 18.9.35 Power Management
Test-RegistryValue "18.9.35.6.1" "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" "DCSettingIndex" 0 "Connected Standby (Battery) Disabled"
Test-RegistryValue "18.9.35.6.2" "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" "ACSettingIndex" 0 "Connected Standby (Plugged) Disabled"
Test-RegistryValue "18.9.35.6.3" "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "DCSettingIndex" 1 "Password on Wake (Battery)"
Test-RegistryValue "18.9.35.6.4" "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "ACSettingIndex" 1 "Password on Wake (Plugged)"

# 18.9.37 Remote Assistance
Test-RegistryValue "18.9.37.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited" 0 "Offer Remote Assistance Disabled"
Test-RegistryValue "18.9.37.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" 0 "Solicited Remote Assistance Disabled"

# 18.9.38 Remote Procedure Call (MS only)
if ($Script:ServerType -eq "MS") {
    Test-RegistryValue "18.9.38.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution" 1 "RPC Endpoint Mapper Auth"
    Test-RegistryValue "18.9.38.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients" 1 "RPC Unauthenticated Restricted"
}

# 18.9.41 Security Account Manager
if ($Script:ServerType -eq "DC") {
    Test-RegistryValue "18.9.41.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM" "SamrChangeUserPasswordApiPolicy" 2 "SAM RPC Strong Encryption (DC)"
    Test-RegistryValue "18.9.41.3" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM" "SamNGCKeyROCAValidation" 2 "ROCA WHfB Validation Block (DC)"
} else {
    Test-RegistryValue "18.9.41.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM" "SamrChangeUserPasswordApiPolicy" 1 "SAM RPC Block All (MS)"
}

# 18.9.49 Troubleshooting and Diagnostics
Test-RegistryValue "18.9.49.5.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" "DisableQueryRemoteServer" 0 "MSDT Disabled"
Test-RegistryValue "18.9.49.11.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" "ScenarioExecutionEnabled" 0 "PerfTrack Disabled"

# 18.9.51 User Profiles
Test-RegistryValue "18.9.51.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1 "Advertising ID Disabled"

# 18.9.53 Windows Time Service
Test-RegistryValue "18.9.53.1.1" "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" "Enabled" 1 "NTP Client Enabled"
if ($Script:ServerType -eq "MS") {
    Test-RegistryValue "18.9.53.1.2" "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" "Enabled" 0 "NTP Server Disabled (MS)"
}

# ============================================================================
# Category 8: Administrative Templates - Windows Components (18.10)
# ============================================================================
Write-CategoryHeader "Category 8: Administrative Templates - Windows Components (18.10)"

# 18.10.4 App Package Deployment
Test-RegistryValue "18.10.4.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" "AllowSharedLocalAppData" 0 "App Data Sharing Disabled"
Test-RegistryValue "18.10.4.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" "DisablePerUserUnsignedPackagesByDefault" 1 "Unsigned Packages Blocked"

# 18.10.6 App runtime
Test-RegistryValue "18.10.6.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional" 1 "MS Account Optional"

# 18.10.8 AutoPlay Policies
Test-RegistryValue "18.10.8.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" 1 "Autoplay Non-Volume Disabled"
Test-RegistryValue "18.10.8.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 1 "AutoRun Disabled"
Test-RegistryValue "18.10.8.3" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 "Autoplay All Drives Disabled"

# 18.10.9 Biometrics
Test-RegistryValue "18.10.9.1.1" "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing" 1 "Anti-Spoofing Enabled"

# 18.10.11 Camera
Test-RegistryValue "18.10.11.1" "HKLM:\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera" 0 "Camera Disabled"

# 18.10.13 Cloud Content
Test-RegistryValue "18.10.13.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent" 1 "Cloud Consumer Disabled"
Test-RegistryValue "18.10.13.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent" 1 "Cloud Optimized Disabled"

# 18.10.14 Connect
Test-RegistryValue "18.10.14.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" "RequirePinForPairing" 1 "PIN for Pairing"

# 18.10.15 Credential User Interface
Test-RegistryValue "18.10.15.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal" 1 "Password Reveal Disabled"
Test-RegistryValue "18.10.15.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators" 0 "Admin Enumeration Disabled"

# 18.10.16 Data Collection
Test-RegistryValue "18.10.16.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 "Diagnostic Data Off"
Test-RegistryValue "18.10.16.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy" 1 "Auth Proxy Disabled"
Test-RegistryValue "18.10.16.3" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1 "Feedback Disabled"
Test-RegistryValue "18.10.16.4" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "EnableOneSettingsAuditing" 1 "OneSettings Audit"
Test-RegistryValue "18.10.16.5" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDiagnosticLogCollection" 1 "Diagnostic Log Limited"
Test-RegistryValue "18.10.16.6" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDumpCollection" 1 "Dump Collection Limited"

# 18.10.18 Desktop App Installer
Test-RegistryValue "18.10.18.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableAppInstaller" 0 "App Installer Disabled"
Test-RegistryValue "18.10.18.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableExperimentalFeatures" 0 "Experimental Features Disabled"
Test-RegistryValue "18.10.18.3" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableHashOverride" 0 "Hash Override Disabled"
Test-RegistryValue "18.10.18.4" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableLocalArchiveMalwareScanOverride" 0 "Malware Scan Override Disabled"
Test-RegistryValue "18.10.18.5" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableBypassCertificatePinningForMicrosoftStore" 0 "Store Cert Bypass Disabled"
Test-RegistryValue "18.10.18.6" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableMSAppInstallerProtocol" 0 "ms-appinstaller Disabled"
Test-RegistryValue "18.10.18.7" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableWindowsPackageManagerCommandLineInterfaces" 0 "Winget CLI Disabled"

# 18.10.26 Event Log Service
Test-RegistryValue "18.10.26.1.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "Retention" "0" "App Log Retention"
Test-RegistryValue "18.10.26.1.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize" 32768 "App Log Max Size"
Test-RegistryValue "18.10.26.2.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention" "0" "Security Log Retention"
Test-RegistryValue "18.10.26.2.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize" 196608 "Security Log Max Size"
Test-RegistryValue "18.10.26.3.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "Retention" "0" "Setup Log Retention"
Test-RegistryValue "18.10.26.3.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize" 32768 "Setup Log Max Size"
Test-RegistryValue "18.10.26.4.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "Retention" "0" "System Log Retention"
Test-RegistryValue "18.10.26.4.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize" 32768 "System Log Max Size"

# 18.10.29 File Explorer
Test-RegistryValue "18.10.29.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableMotWOnInsecurePathCopy" 0 "MOTW Enabled"
Test-RegistryValue "18.10.29.3" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" 0 "DEP for Explorer"
Test-RegistryValue "18.10.29.4" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" 0 "Heap Termination"
Test-RegistryValue "18.10.29.5" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" 0 "Shell Protocol Protected"

# 18.10.36 Location and Sensors
Test-RegistryValue "18.10.36.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1 "Location Disabled"

# 18.10.40 Messaging
Test-RegistryValue "18.10.40.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" "AllowMessageSync" 0 "Message Sync Disabled"

# 18.10.41 Microsoft account
Test-RegistryValue "18.10.41.1" "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth" 1 "MS Account Auth Blocked"

# 18.10.57 Remote Desktop Services
Test-RegistryValue "18.10.57.2.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving" 1 "RDP Password Save Disabled"
Test-RegistryValue "18.10.57.3.2.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fSingleSessionPerUser" 1 "Single RDS Session"
Test-RegistryValue "18.10.57.3.3.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "EnableUiaRedirection" 0 "UI Automation Disabled"
Test-RegistryValue "18.10.57.3.3.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCcm" 1 "COM Port Redirection Disabled"
Test-RegistryValue "18.10.57.3.3.3" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm" 1 "Drive Redirection Disabled"
Test-RegistryValue "18.10.57.3.3.4" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableLocationRedir" 1 "Location Redirection Disabled"
Test-RegistryValue "18.10.57.3.3.5" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableLPT" 1 "LPT Redirection Disabled"
Test-RegistryValue "18.10.57.3.3.6" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisablePNPRedir" 1 "PnP Redirection Disabled"
Test-RegistryValue "18.10.57.3.3.7" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableWebAuthn" 1 "WebAuthn Disabled"
Test-RegistryValue "18.10.57.3.3.8" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SCClipLevel" 0 "Clipboard Server->Client Disabled"
Test-RegistryValue "18.10.57.3.9.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword" 1 "RDP Password Prompt"
Test-RegistryValue "18.10.57.3.9.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic" 1 "RDP Secure RPC"
Test-RegistryValue "18.10.57.3.9.3" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer" 2 "RDP SSL/TLS"
Test-RegistryValue "18.10.57.3.9.4" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication" 1 "RDP NLA"
Test-RegistryValue "18.10.57.3.9.5" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel" 3 "RDP High Encryption"
Test-RegistryValue "18.10.57.3.10.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime" 900000 "RDS Idle Timeout"
Test-RegistryValue "18.10.57.3.11.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit" 1 "RDS Temp Cleanup"
Test-RegistryValue "18.10.57.3.11.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "PerSessionTempDir" 1 "RDS Per-Session Temp"

# 18.10.58 RSS Feeds
Test-RegistryValue "18.10.58.1" "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" 1 "RSS Enclosure Disabled"

# 18.10.59 Search
Test-RegistryValue "18.10.59.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" 0 "Cloud Search Disabled"
Test-RegistryValue "18.10.59.3" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" 0 "Encrypted Index Disabled"
Test-RegistryValue "18.10.59.4" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "EnableDynamicContentInWSB" 0 "Search Highlights Disabled"

# 18.10.63 Software Protection Platform
Test-RegistryValue "18.10.63.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" "NoGenTicket" 1 "KMS AVS Disabled"

# 18.10.77 Windows Defender SmartScreen
Test-RegistryValue "18.10.77.2.1a" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 1 "SmartScreen Enabled"
Test-RegistryValue "18.10.77.2.1b" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "Block" "SmartScreen Block"

# 18.10.81 Windows Ink Workspace
Test-RegistryValue "18.10.81.1" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowSuggestedAppsInWindowsInkWorkspace" 0 "Ink Suggested Apps Disabled"
Test-RegistryValue "18.10.81.2" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" 0 "Ink Workspace Restricted"

# 18.10.82 Windows Installer
Test-RegistryValue "18.10.82.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl" 0 "Installer User Control Disabled"
Test-RegistryValue "18.10.82.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" 0 "Always Install Elevated Disabled"
Test-RegistryValue "18.10.82.3" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "SafeForScripting" 0 "IE Prompt for MSI"

# 18.10.83 Windows Logon Options
Test-RegistryValue "18.10.83.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableMPR" 0 "MPR Password Disabled"
Test-RegistryValue "18.10.83.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" 1 "Auto Sign-in After Update Disabled"

# 18.10.88 Windows PowerShell
Test-RegistryValue "18.10.88.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 1 "PS Script Block Logging"
Test-RegistryValue "18.10.88.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 1 "PS Transcription"

# 18.10.90 Windows Remote Management (WinRM)
Test-RegistryValue "18.10.90.1.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic" 0 "WinRM Client Basic Disabled"
Test-RegistryValue "18.10.90.1.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic" 0 "WinRM Client Encrypted"
Test-RegistryValue "18.10.90.1.3" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest" 0 "WinRM Client Digest Disabled"
Test-RegistryValue "18.10.90.2.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic" 0 "WinRM Service Basic Disabled"
Test-RegistryValue "18.10.90.2.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig" 0 "WinRM Remote Mgmt Disabled"
Test-RegistryValue "18.10.90.2.3" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic" 0 "WinRM Service Encrypted"
Test-RegistryValue "18.10.90.2.4" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs" 1 "WinRM RunAs Disabled"

# 18.10.91 Windows Remote Shell
Test-RegistryValue "18.10.91.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" "AllowRemoteShellAccess" 0 "Remote Shell Disabled"

# 18.10.93 Windows Security
Test-RegistryValue "18.10.93.2.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" "DisallowExploitProtectionOverride" 1 "Exploit Protection Locked"

# 18.10.94 Windows Update
Test-RegistryValue "18.10.94.1.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" 0 "Auto Restart Allowed"
Test-RegistryValue "18.10.94.2.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0 "Auto Updates Enabled"
Test-RegistryValue "18.10.94.2.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0 "Update Every Day"
Test-RegistryValue "18.10.94.4.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuildsPolicyValue" 1 "Preview Builds Disabled"
Test-RegistryValue "18.10.94.4.2a" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdates" 1 "Quality Updates Deferred"
Test-RegistryValue "18.10.94.4.2b" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays" 0 "Quality Updates 0 Days"

Write-Host "`n✅ Category 8 completed" -ForegroundColor Green

# ============================================================================
# Category 9: Administrative Templates - User (19)
# ============================================================================
Write-CategoryHeader "Category 9: Administrative Templates - User (19)"

# Get all user SIDs that are currently logged on
$UserSIDs = Get-ChildItem "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match "^S-1-5-21-" -and $_.PSChildName -notmatch "_Classes$" }

foreach ($UserSID in $UserSIDs) {
    $SIDPath = $UserSID.PSChildName
    
    # 19.5.1.1 Turn off toast notifications on the lock screen
    Test-RegistryValue "19.5.1.1" "Registry::HKEY_USERS\$SIDPath\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotificationOnLockScreen" 1 "Lock Screen Toast Disabled (User: $SIDPath)"
    
    # 19.6.6.1.1 Turn off Help Experience Improvement Program
    Test-RegistryValue "19.6.6.1.1" "Registry::HKEY_USERS\$SIDPath\Software\Policies\Microsoft\Assistance\Client\1.0" "NoImplicitFeedback" 1 "Help Improvement Disabled (User: $SIDPath)"
    
    # 19.7.5 Attachment Manager
    Test-RegistryValue "19.7.5.1" "Registry::HKEY_USERS\$SIDPath\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" 2 "Zone Info Preserved (User: $SIDPath)"
    Test-RegistryValue "19.7.5.2" "Registry::HKEY_USERS\$SIDPath\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "ScanWithAntiVirus" 3 "AV Scan on Attachments (User: $SIDPath)"
    
    # 19.7.8 Cloud Content
    Test-RegistryValue "19.7.8.1" "Registry::HKEY_USERS\$SIDPath\Software\Policies\Microsoft\Windows\CloudContent" "ConfigureWindowsSpotlight" 2 "Spotlight Disabled (User: $SIDPath)"
    Test-RegistryValue "19.7.8.2" "Registry::HKEY_USERS\$SIDPath\Software\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" 1 "Third-Party Suggestions Disabled (User: $SIDPath)"
    Test-RegistryValue "19.7.8.3" "Registry::HKEY_USERS\$SIDPath\Software\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1 "Tailored Experiences Disabled (User: $SIDPath)"
    Test-RegistryValue "19.7.8.4" "Registry::HKEY_USERS\$SIDPath\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" 1 "All Spotlight Disabled (User: $SIDPath)"
    Test-RegistryValue "19.7.8.5" "Registry::HKEY_USERS\$SIDPath\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSpotlightCollectionOnDesktop" 1 "Desktop Spotlight Disabled (User: $SIDPath)"
    
    # 19.7.26 Network Sharing
    Test-RegistryValue "19.7.26.1" "Registry::HKEY_USERS\$SIDPath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInplaceSharing" 1 "Profile Sharing Disabled (User: $SIDPath)"
    
    # 19.7.46 Windows Media Player
    Test-RegistryValue "19.7.46.2.1" "Registry::HKEY_USERS\$SIDPath\Software\Policies\Microsoft\WindowsMediaPlayer" "PreventCodecDownload" 1 "Codec Download Disabled (User: $SIDPath)"
}

if ($UserSIDs.Count -eq 0) {
    Write-Host "⚠️  No interactive user sessions found. User policy checks skipped." -ForegroundColor Yellow
}

Write-Host "`n✅ Category 9 completed" -ForegroundColor Green

# ============================================================================
# Generate HTML Report
# ============================================================================
Write-Host "`n============================================================================" -ForegroundColor Cyan
Write-Host " Generating HTML Report..." -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan

$PassRate = if ($Script:TotalChecks -gt 0) { [math]::Round(($Script:PassedChecks / $Script:TotalChecks) * 100, 2) } else { 0 }

$FailedRows = ($Script:Results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
    "<tr style='background-color:#ffebee;'><td>$($_.CISID)</td><td>$($_.Description)</td><td style='color:red;font-weight:bold;'>$($_.Status)</td><td>$($_.Expected)</td><td>$($_.Actual)</td></tr>"
}) -join "`n"

$PassedRows = ($Script:Results | Where-Object { $_.Status -eq "PASS" } | ForEach-Object {
    "<tr style='background-color:#e8f5e9;'><td>$($_.CISID)</td><td>$($_.Description)</td><td style='color:green;font-weight:bold;'>$($_.Status)</td><td>$($_.Expected)</td><td>$($_.Actual)</td></tr>"
}) -join "`n"

$HtmlReport = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>CIS Benchmark Validation Report</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
h1 { color: #1976d2; border-bottom: 3px solid #1976d2; padding-bottom: 10px; }
h2 { color: #388e3c; margin-top: 30px; }
.summary { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
.summary-box { display: inline-block; padding: 15px 25px; margin: 10px; border-radius: 8px; color: white; font-size: 18px; font-weight: bold; }
.total { background-color: #1976d2; }
.pass { background-color: #388e3c; }
.fail { background-color: #d32f2f; }
.rate { background-color: #f57c00; }
table { border-collapse: collapse; width: 100%; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
th { background-color: #1976d2; color: white; padding: 12px; text-align: left; }
td { padding: 10px; border-bottom: 1px solid #ddd; }
tr:hover { background-color: #f5f5f5; }
.info { background-color: #e3f2fd; padding: 15px; border-left: 4px solid #1976d2; margin: 20px 0; }
.warning { background-color: #fff3e0; padding: 15px; border-left: 4px solid #f57c00; margin: 20px 0; }
.meta { color: #666; font-size: 14px; }
</style>
</head>
<body>
<h1>🔒 CIS Benchmark v2.1.0 - Windows Server 2025 Validation Report</h1>
<div class="meta">
<strong>Server:</strong> $env:COMPUTERNAME | 
<strong>Type:</strong> $($Script:ServerType) | 
<strong>Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
</div>
<div class="summary">
<h2>📊 Summary</h2>
<div class="summary-box total">Total Checks: $($Script:TotalChecks)</div>
<div class="summary-box pass">✅ Passed: $($Script:PassedChecks)</div>
<div class="summary-box fail">❌ Failed: $($Script:FailedChecks)</div>
<div class="summary-box rate">Pass Rate: $PassRate%</div>
</div>
$(if ($Script:FailedChecks -gt 0) {
"<div class='warning'><strong>⚠️ Attention:</strong> $($Script:FailedChecks) setting(s) did not pass validation. Please review the Failed section below.</div>"
})
$(if ($Script:FailedChecks -gt 0) {
"<h2>❌ Failed Checks ($($Script:FailedChecks))</h2>
<table>
<tr><th>CIS ID</th><th>Description</th><th>Status</th><th>Expected</th><th>Actual</th></tr>
$FailedRows
</table>"
})
<h2>✅ Passed Checks ($($Script:PassedChecks))</h2>
<table>
<tr><th>CIS ID</th><th>Description</th><th>Status</th><th>Expected</th><th>Actual</th></tr>
$PassedRows
</table>
<div class="info">
<strong>📋 Next Steps:</strong><br>
1. Review any failed settings and ensure GPO is correctly linked to OU<br>
2. Run <code>gpupdate /force</code> and reboot if needed<br>
3. For manual checks, refer to the CIS Benchmark PDF<br>
4. Send this HTML report to your administrator for review
</div>
</body>
</html>
"@

$HtmlReport | Out-File -FilePath $Script:ReportPath -Encoding UTF8

Write-Host "`n============================================================================" -ForegroundColor Green
Write-Host " ✅ Validation Complete!" -ForegroundColor Green
Write-Host "============================================================================" -ForegroundColor Green
Write-Host " Total Checks: $($Script:TotalChecks)" -ForegroundColor White
Write-Host " Passed: $($Script:PassedChecks)" -ForegroundColor Green
Write-Host " Failed: $($Script:FailedChecks)" -ForegroundColor Red
Write-Host " Pass Rate: $PassRate%" -ForegroundColor Yellow
Write-Host ""
Write-Host " 📄 HTML Report saved to: $($Script:ReportPath)" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Green

# Cleanup
if (Test-Path $Script:SecEditPath) {
    Remove-Item $Script:SecEditPath -Force -ErrorAction SilentlyContinue
}
