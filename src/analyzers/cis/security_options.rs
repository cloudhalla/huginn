use crate::analyzers::Analyzer;
use crate::error::HuginnError;
use crate::models::finding::{Category, ComplianceRef, Finding, Severity};
use crate::models::system_info::SystemInfo;

pub struct UacAnalyzer;

impl Analyzer for UacAnalyzer {
    fn id(&self) -> &'static str {
        "cis-2.3.7"
    }

    fn name(&self) -> &'static str {
        "CIS §2.3.7 — User Account Control (UAC)"
    }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();
        let sec = &info.security;

        // CIS 2.3.7.1 — UAC must be enabled
        if let Some(uac_enabled) = sec.uac_enabled {
            if !uac_enabled {
                findings.push(
                    Finding::fail(
                        "CIS-2.3.7.1",
                        "User Account Control (UAC) is disabled",
                        Severity::Critical,
                        Category::SystemIntegrity,
                        "UAC disabled means all processes run with full administrative privileges \
                         by default. This allows malware and malicious scripts to make system-wide \
                         changes without any elevation prompt, dramatically increasing the blast \
                         radius of any compromise.",
                        "Disabled",
                        "Enabled",
                        "Enable UAC via: Computer Configuration > Windows Settings > Security \
                         Settings > Local Policies > Security Options > 'User Account Control: \
                         Run all administrators in Admin Approval Mode' = Enabled. Registry: \
                         HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ \
                         EnableLUA = 1.",
                    )
                    .with_refs(vec![
                        ComplianceRef::cis(
                            "CIS WS2022 2.3.17.1",
                            "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'",
                        ),
                        ComplianceRef::nist("NIST AC-6(5)", "Least Privilege | Privileged Accounts"),
                    ]),
                );
            } else {
                findings.push(Finding::pass(
                    "CIS-2.3.7.1",
                    "User Account Control (UAC) is enabled",
                    Category::SystemIntegrity,
                ));
            }
        }

        // CIS 2.3.7.2 — UAC elevation prompt on secure desktop
        if let Some(secure_desktop) = sec.secure_desktop {
            if !secure_desktop {
                findings.push(
                    Finding::fail(
                        "CIS-2.3.7.2",
                        "UAC elevation prompt does not use secure desktop",
                        Severity::Medium,
                        Category::SystemIntegrity,
                        "Without the secure desktop, the UAC prompt appears on the regular \
                         desktop where malicious software can spoof it or inject keystrokes. \
                         The secure desktop prevents other processes from interacting with the \
                         elevation dialog.",
                        "Disabled",
                        "Enabled",
                        "Enable: Computer Configuration > Windows Settings > Security Settings > \
                         Local Policies > Security Options > 'User Account Control: Switch to the \
                         secure desktop when prompting for elevation' = Enabled.",
                    )
                    .with_refs(vec![ComplianceRef::cis(
                        "CIS WS2022 2.3.17.2",
                        "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'",
                    )]),
                );
            }
        }

        // UAC level check (level 0 = never notify is the worst)
        if let Some(level) = sec.uac_level {
            if level == 0 {
                findings.push(
                    Finding::fail(
                        "CIS-2.3.7.3",
                        "UAC is set to 'Never notify' mode",
                        Severity::High,
                        Category::SystemIntegrity,
                        "UAC set to 'Never notify' means no elevation prompts are shown, \
                         allowing any process to silently elevate privileges. This is \
                         functionally equivalent to disabling UAC.",
                        "Never notify (level 0)",
                        "Notify when apps make changes (level 2 or 3)",
                        "Increase the UAC notification level via the Control Panel or \
                         Group Policy.",
                    )
                    .with_refs(vec![ComplianceRef::cis(
                        "CIS WS2022 2.3.17.6",
                        "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'",
                    )]),
                );
            }
        }

        Ok(findings)
    }
}

pub struct LsaProtectionAnalyzer;

impl Analyzer for LsaProtectionAnalyzer {
    fn id(&self) -> &'static str {
        "cis-2.3.11"
    }

    fn name(&self) -> &'static str {
        "CIS §2.3.11 — LSA Protection"
    }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();
        let sec = &info.security;

        // LSA Protection (PPL)
        if let Some(lsa_protection) = sec.lsa_protection {
            if !lsa_protection {
                findings.push(
                    Finding::fail(
                        "CIS-8.1.1",
                        "LSA Protection (RunAsPPL) is not enabled",
                        Severity::High,
                        Category::SystemIntegrity,
                        "Without LSA protection, tools like Mimikatz can read credentials \
                         from LSASS memory using standard user-mode APIs. Enabling PPL (Protected \
                         Process Light) prevents non-protected processes from accessing LSASS \
                         memory, significantly raising the bar for credential theft.",
                        "Disabled",
                        "Enabled (RunAsPPL = 1)",
                        "Enable LSA protection via registry: HKLM\\SYSTEM\\CurrentControlSet\\ \
                         Control\\Lsa\\RunAsPPL = 1 (DWORD). A reboot is required. Also configure \
                         via Group Policy: Computer Configuration > Administrative Templates > \
                         System > Local Security Authority > 'Configure LSASS to run as a \
                         protected process'.",
                    )
                    .with_refs(vec![
                        ComplianceRef::cis(
                            "CIS WS2022 18.3.2",
                            "Ensure 'Configure LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'",
                        ),
                        ComplianceRef::nist("NIST SI-7", "Software, Firmware, and Information Integrity"),
                    ]),
                );
            } else {
                findings.push(Finding::pass(
                    "CIS-8.1.1",
                    "LSA Protection (RunAsPPL) is enabled",
                    Category::SystemIntegrity,
                ));
            }
        }

        // Credential Guard
        if let Some(cred_guard) = sec.credential_guard {
            if !cred_guard {
                findings.push(
                    Finding::fail(
                        "CIS-8.1.2",
                        "Windows Credential Guard is not enabled",
                        Severity::High,
                        Category::SystemIntegrity,
                        "Credential Guard uses hardware-based virtualization to protect \
                         credentials in an isolated environment. Without it, domain credentials \
                         stored in LSASS can be extracted by attackers with local admin access.",
                        "Disabled",
                        "Enabled",
                        "Enable Credential Guard via Group Policy: Computer Configuration > \
                         Administrative Templates > System > Device Guard > \
                         'Turn On Virtualization Based Security'. Requires VBS-capable hardware \
                         (TPM 2.0, UEFI Secure Boot).",
                    )
                    .with_refs(vec![
                        ComplianceRef::cis(
                            "CIS WS2022 18.9.4.1",
                            "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'",
                        ),
                        ComplianceRef::nist("NIST AC-17(2)", "Remote Access | Protection of Confidentiality and Integrity Using Encryption"),
                    ]),
                );
            }
        }

        // Windows Defender checks
        if let Some(defender) = sec.defender_enabled {
            if !defender {
                findings.push(
                    Finding::fail(
                        "CIS-5.1",
                        "Windows Defender is disabled",
                        Severity::Critical,
                        Category::SoftwareSecurity,
                        "Windows Defender provides real-time malware protection. Disabling it \
                         leaves the system without any built-in malware detection and response \
                         capabilities.",
                        "Disabled",
                        "Enabled",
                        "Enable Windows Defender via Windows Security settings or Group Policy: \
                         Computer Configuration > Administrative Templates > Windows Components > \
                         Microsoft Defender Antivirus > 'Turn off Microsoft Defender Antivirus'.",
                    )
                    .with_refs(vec![ComplianceRef::nist(
                        "NIST SI-3",
                        "Malicious Code Protection",
                    )]),
                );
            } else if sec.defender_real_time == Some(false) {
                findings.push(
                    Finding::fail(
                        "CIS-5.2",
                        "Windows Defender real-time protection is disabled",
                        Severity::High,
                        Category::SoftwareSecurity,
                        "Real-time protection monitors the system continuously for malware. \
                         Without it, threats are only detected on scheduled scans or manual \
                         inspection.",
                        "Real-time protection disabled",
                        "Real-time protection enabled",
                        "Enable real-time protection in Windows Security settings or via \
                         registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\ \
                         Real-Time Protection\\DisableRealtimeMonitoring = 0.",
                    )
                    .with_refs(vec![ComplianceRef::nist("NIST SI-3(1)", "Malicious Code Protection | Central Management")]),
                );
            }
        }

        Ok(findings)
    }
}
