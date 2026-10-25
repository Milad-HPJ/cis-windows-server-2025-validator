# CIS Windows Server 2025 Validator

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202025-0078D6?logo=windows&logoColor=white)
![Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v2.1.0-2E7D32)
![Mode](https://img.shields.io/badge/Mode-Read--Only%20Audit-orange)

A comprehensive, read-only PowerShell validation tool for auditing **Microsoft Windows Server 2025** security configurations against the **CIS Microsoft Windows Server 2025 Benchmark v2.1.0**.

The script inspects local security policies, audit subcategories, service states, and registry-backed Group Policy settings, displays real-time results in the console, and generates a standalone HTML compliance report comparing expected and detected values.

> **Important:** This is an independent, read-only validation tool. It makes **zero changes** to the target system. It is not an official CIS product, is not certified by CIS, and does not establish formal CIS Benchmark certification.

---

## Features

- **Interactive Server Role Selection:** Choose between **Domain Controller (DC)** and **Member Server (MS)** at startup so role-specific (`DC only` / `MS only`) controls are evaluated accurately.
- **Strictly Read-Only Execution:** Performs passive inspection using `secedit /export`, `auditpol /get`, and registry reads without modifying any system settings, services, or policies.
- **Comprehensive CIS v2.1.0 Coverage:** Evaluates over 420 checks across Sections 1, 2, 5, 9, 17, 18, and 19, including range-based, threshold, and multi-value validations.
- **One-Click Batch Launcher:** Includes `Run-CIS-Validator.bat` to automatically request Administrator elevation and bypass process-scoped PowerShell execution policy restrictions.
- **Self-Contained HTML Report:** Generates a clean, color-coded HTML report summarizing total checks, passed/failed counts, overall compliance percentage, and detailed check tables.
- **PowerShell 5.1 & 7+ Compatible:** Works out-of-the-box on default Windows Server 2025 installations.

---

## Validation Coverage

The script validates recommendations across the following **CIS Microsoft Windows Server 2025 Benchmark v2.1.0** sections:

| CIS Section | Area | Coverage |
|---|---|---|
| **Section 1** | Account Policies | Password Policy (`1.1.1` – `1.1.7`) and Account Lockout Policy (`1.2.1` – `1.2.4`) |
| **Section 2.2** | User Rights Assignment | All 48 privilege rights (`2.2.1` – `2.2.48`) evaluated for DC and MS profiles |
| **Section 2.3** | Security Options | Accounts, Audit, Devices, Domain Controller, Domain Member, Interactive Logon, Network Client/Server, Network Access, Network Security, Shutdown, System Objects, and UAC |
| **Section 5** | System Services | Print Spooler (`Spooler`) service startup state (`5.1` / `5.2`) |
| **Section 9** | Windows Defender Firewall | Domain (`9.1`), Private (`9.2`), and Public (`9.3`) firewall profiles and logging settings |
| **Section 17** | Advanced Audit Policy | Account Logon, Account Management, Detailed Tracking, DS Access, Logon/Logoff, Object Access, Policy Change, Privilege Use, and System subcategories |
| **Section 18.1 – 18.8** | Administrative Templates (Computer) | Control Panel (`18.1`), MS Security Guide (`18.4`), MSS Legacy (`18.5`), Network (`18.6`), Printers (`18.7`), and Start Menu (`18.8`) |
| **Section 18.9** | Administrative Templates — System | Process Creation, Credentials Delegation, Device Guard / VBS, Early Launch, Group Policy, Internet Communication, Kerberos, Kernel DMA, LAPS, LSASS, Logon, Power, Remote Assistance, RPC, SAM, Diagnostics, and Windows Time |
| **Section 18.10 – 18.11** | Administrative Templates — Windows Components & Custom | App Package Deployment, AutoPlay, Biometrics, Camera, Cloud Content, Connect, CredUI, Data Collection, App Installer, Event Log Service, File Explorer, Location, Messaging, Microsoft Account, RDS/RDP, RSS, Search, SmartScreen, Windows Ink, Windows Installer, Logon Options, PowerShell, WinRM, WinRS, Windows Security, Windows Update, and WPAD/Proxy Custom Settings |
| **Section 19** | Administrative Templates (User) | Lock Screen Notifications, Help Experience, Attachment Manager, Cloud Content / Spotlight, Network Sharing, and Windows Media Player (`19.5` – `19.7`) |

**Coverage Note:** While this script covers the vast majority of automated and registry/policy-backed recommendations in the Benchmark, certain environment-specific exceptions or organizational baselines may still require manual review.

---

## Screenshots

> *(Screenshots can be placed in the `screenshots/` directory)*

### Console Execution
<!-- Uncomment the line below after uploading screenshots/console-execution.png -->
<!-- ![Console Execution](screenshots/console-execution.png) -->

### HTML Compliance Report
<!-- Uncomment the line below after uploading screenshots/html-report.png -->
<!-- ![HTML Report](screenshots/html-report.png) -->

---

## Requirements

- **Operating System:** Microsoft Windows Server 2025 (Standard or Datacenter).
- **PowerShell:** Windows PowerShell 5.1 (built-in) or PowerShell 7+.
- **Privileges:** Local Administrator or Domain Administrator privileges (required to read `secedit` security policies, `auditpol` settings, and protected registry keys).
- **Disk Space:** Write permission to save the HTML report at `C:\CIS_Benchmark_Validation_Report.html` and temporary export file in `%TEMP%`.

---

## Installation

### Option 1: Clone via Git
```bash
git clone [https://github.com/Milad-HPJ/cis-windows-server-2025-validator.git](https://github.com/Milad-HPJ/cis-windows-server-2025-validator.git)
cd cis-windows-server-2025-validator
```

### Option 2: Direct Download
1. Download `cis-windows-server-2025-validator.ps1` and `Run-CIS-Validator.bat` from this repository (or download the repository as a `.zip` archive and extract it).
2. Place both files in the same folder on the target Windows Server.

---

## Usage

### Method 1: Using the Batch Launcher (Recommended)
1. Right-click **`Run-CIS-Validator.bat`** and select **Run as administrator** (or double-click it and accept the UAC prompt).
2. The launcher automatically opens an elevated PowerShell session with `-ExecutionPolicy Bypass` for that process only.
3. When prompted, select the target server role:
   - `1` — **Domain Controller (DC)**
   - `2` — **Member Server (MS)**
4. Wait for the validation to complete and review the generated report at:
   ```text
   C:\CIS_Benchmark_Validation_Report.html
   ```

### Method 2: Running Directly from PowerShell
1. Open **Windows PowerShell as Administrator**.
2. Navigate to the directory containing the script and bypass the execution policy for the current session:
   ```powershell
   cd C:\Path\To\cis-windows-server-2025-validator
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
   .\cis-windows-server-2025-validator.ps1
   ```
3. Enter `1` (Domain Controller) or `2` (Member Server) when prompted.
4. Open `C:\CIS_Benchmark_Validation_Report.html` in any web browser to view the full results.

---

## Understanding Results

| Status | Meaning |
|---|---|
| `PASS` | The detected configuration matches or satisfies the value/range prescribed by the CIS Benchmark. |
| `FAIL` | The detected value does not meet the expected criteria, or the policy/registry value is not configured (`NOT FOUND`). |

- A `FAIL` result does not necessarily indicate an immediate vulnerability; some Level 2 or Next Generation Windows Security settings may intentionally be omitted depending on server roles and operational requirements.
- A `PASS` result confirms only the technical condition evaluated by the script and does not guarantee complete organizational compliance.

---

## Safety and Operational Guidance

- **Read-Only Design:** The script exports local security policy settings to a temporary `.cfg` file in `%TEMP%` for parsing and automatically deletes the temporary file upon completion. No system settings are modified.
- **Test Before Production Use:** Validate the script in a lab or staging environment before running it across production servers.
- **Protect Generated Reports:** Treat `CIS_Benchmark_Validation_Report.html` as sensitive audit data, as it details the security posture and configuration state of your server.
- **Review Before Remediation:** Always review failed checks against your organization's Group Policy architecture and official CIS Impact Statements before applying hardening changes.

---

## Benchmark Reference & Disclaimer

This project references the **CIS Microsoft Windows Server 2025 Benchmark v2.1.0** for configuration identification and audit mapping.

- Always consult the official, lawfully obtained CIS Benchmark documentation for complete rationale, impact statements, exceptions, and remediation procedures.
- This repository is not affiliated with, sponsored by, or endorsed by the Center for Internet Security (CIS).
- To comply with CIS copyright terms, the CIS Benchmark PDF/documentation is **not** distributed in this repository.

---

## Contributing

Direct pushes to the `main` branch are restricted. Community contributions are welcome through **Issues** and **Pull Requests** and require maintainer review and approval before merging:

1. Fork the repository and create a feature or bugfix branch.
2. Test your changes on a Windows Server 2025 environment (DC and/or MS).
3. Submit a **Pull Request** with a clear description of the changes.
4. Do not include credentials, internal IP addresses, or unredacted production HTML reports in Issues or Pull Requests.

---

## License

This project's original PowerShell and Batch source code is licensed under the **MIT License**.

CIS Benchmark™ names and recommendation titles are the property of the Center for Internet Security (CIS) and are subject to CIS Terms of Use.
