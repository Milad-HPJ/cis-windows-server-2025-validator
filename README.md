# CIS Windows Server 2025 Validator

A PowerShell script for validating selected Windows security settings against the **CIS Microsoft Windows Server 2025 Benchmark v2.1.0**.

The script checks local security configuration, displays results in the console, and generates an HTML report containing the expected and detected values for each check.

> **Important:** This is an independent validation tool. It is not an official CIS product, is not certified by CIS, and does not establish complete CIS Benchmark compliance.

## Features

- **Interactive server selection:** Choose Domain Controller (DC) or Member Server (MS).
- **Configuration validation:** Checks selected security settings against expected values.
- **Console output:** Displays individual check results and a final summary.
- **HTML reporting:** Generates a report containing check IDs, descriptions, statuses, expected values, and actual values.
- **Read-only validation:** Intended to inspect the current configuration rather than apply security remediation.

## Validation Coverage

The script currently includes checks in the following areas:

| Area | Coverage |
|---|---|
| Account Policies | Password and account lockout policies |
| User Rights Assignment | Selected user rights |
| Security Options | Selected registry-based security settings |
| System Services | Selected service-related settings |
| Windows Firewall | Domain, Private, and Public profiles |
| Advanced Audit Policy | Selected audit policy settings |
| Administrative Templates — System | Selected system policies |
| Administrative Templates — Windows Components | Selected Windows component policies |
| Administrative Templates — User | Selected user policies |

**Coverage limitation:** This list describes the areas addressed by the script, not complete coverage of every recommendation in the Benchmark. Some recommendations require manual verification or are not implemented in this version.

## Requirements

- Windows Server with PowerShell available.
- Administrator privileges.
- Access to the built-in Windows security-policy and registry interfaces used by the checks.
- Sufficient permissions and free disk space to create the report at `C:\CIS_Benchmark_Validation_Report.html`.

The script is intended for Windows Server security validation. Compatibility and accuracy should be tested on each supported operating-system version before operational use.

## Installation

1. Open this repository on GitHub.
2. Download `cis-windows-server-2025-validator.ps1` using the file's download option.
3. Save the script to a directory on the target Windows Server.

Alternatively, clone the repository if Git is installed and configured on the target system.

## Usage

1. Open **Windows PowerShell as Administrator**.
2. Navigate to the directory containing the script.
3. Run:

   ```powershell
   .\cis-windows-server-2025-validator.ps1
   ```

4. When prompted, select the server type:

   - `1` — Domain Controller
   - `2` — Member Server

5. Allow the validation to finish and review the console summary.
6. Open the generated HTML report:

   ```text
   C:\CIS_Benchmark_Validation_Report.html
   ```

The report includes the total number of checks, passed and failed counts, the pass rate, and details for individual checks.

**Note:** If the server-type selection is invalid, the current script defaults to Member Server. Select the correct type deliberately, especially when validating a Domain Controller.

## Understanding Results

| Status | Meaning |
|---|---|
| `PASS` | The detected value matches the value expected by the script. |
| `FAIL` | The detected value does not match the expected value, or the value could not be found or read. |

A `FAIL` result does not necessarily prove that a server is insecure. Review the actual value, applicability, effective Group Policy settings, and relevant Benchmark guidance before deciding on remediation.

A `PASS` result confirms only the condition checked by the script. It does not guarantee overall security or compliance.

## Safety and Operational Guidance

- Test the script in a lab or non-production environment before using it on production servers.
- Review the script before execution and confirm that it is appropriate for the target system.
- Keep a suitable backup and recovery plan for critical systems.
- Treat the HTML report as potentially sensitive because it may reveal server configuration details.
- Review failed checks individually before changing Group Policy or local security settings.
- Do not apply remediation automatically based only on this report.

The script exports the local security policy to a temporary file for inspection and removes that temporary file during cleanup. The intended validation workflow does not apply security remediation.

## Limitations

- The checks are limited to those implemented in the current script.
- Some recommendations may require manual assessment.
- Results depend on the server's current configuration and the ability to read the relevant settings.
- Domain Controller and Member Server applicability must be selected correctly.
- The script has not been independently certified as a complete or authoritative CIS compliance assessment.

## Benchmark Reference

This project references the **CIS Microsoft Windows Server 2025 Benchmark v2.1.0**.

Use the applicable, lawfully obtained Benchmark documentation to understand recommendations, applicability, exceptions, and remediation procedures.

This repository does not represent an endorsement by CIS. The CIS name and Benchmark are referenced for identification of the configuration standard.

## Contributing

Contributions are welcome. Useful contributions include:

- Bug reports and reproducible validation errors.
- Testing results from supported Windows Server environments.
- Improvements to error handling and reporting.
- Additional independently implemented checks.
- Documentation improvements.

Please describe the Windows Server version, server role, relevant configuration, and steps to reproduce an issue. Do not include credentials, sensitive configuration data, or unredacted production reports.

## License and Third-Party Rights

No license is declared by this README. Before redistributing this project publicly, choose an appropriate license for your original code and review the applicable terms governing any third-party material included in the script.

The CIS Benchmark documentation and associated content may be subject to separate copyright and licensing restrictions. Do not include the full Benchmark document or assume that a public code license grants permission to redistribute CIS material.
