use crate::analyzers::Analyzer;
use crate::error::HuginnError;
use crate::models::finding::{Category, ComplianceRef, Finding, Severity};
use crate::models::system_info::SystemInfo;

pub struct FirewallAnalyzer;

impl Analyzer for FirewallAnalyzer {
    fn id(&self) -> &'static str {
        "cis-9.fw"
    }

    fn name(&self) -> &'static str {
        "CIS §9 — Windows Firewall"
    }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();

        if info.network.firewall_profiles.is_empty() {
            findings.push(
                Finding::fail(
                    "CIS-9.0",
                    "Firewall status could not be determined",
                    Severity::Medium,
                    Category::FirewallPolicy,
                    "Unable to retrieve firewall profile data. This may indicate the firewall \
                     management service is not running or access was denied.",
                    "Unknown",
                    "All profiles enabled with inbound default block",
                    "Ensure the firewall service is running and re-run with elevated privileges.",
                ),
            );
            return Ok(findings);
        }

        for profile in &info.network.firewall_profiles {
            let rule_id = format!("CIS-9.{}", profile.name.to_lowercase().replace(' ', "-"));

            if !profile.enabled {
                let severity = if profile.name.to_lowercase().contains("public") {
                    Severity::Critical
                } else {
                    Severity::High
                };

                findings.push(
                    Finding::fail(
                        rule_id.as_str(),
                        format!(
                            "Windows Firewall '{}' profile is disabled",
                            profile.name
                        ),
                        severity,
                        Category::FirewallPolicy,
                        format!(
                            "The {} firewall profile is disabled, leaving the system unprotected \
                             from network-based attacks in that network context. The Public \
                             profile is especially critical as it applies when connected to \
                             untrusted networks.",
                            profile.name
                        ),
                        "Disabled",
                        "Enabled",
                        format!(
                            "Enable the {} firewall profile via Windows Defender Firewall \
                             with Advanced Security, or via Group Policy: Computer Configuration > \
                             Windows Settings > Security Settings > Windows Defender Firewall with \
                             Advanced Security > Windows Defender Firewall Properties > {} Profile \
                             > Firewall state: On.",
                            profile.name, profile.name
                        ),
                    )
                    .with_refs(vec![ComplianceRef::cis(
                        format!("CIS WS2022 9.{}.1", {
                            match profile.name.to_lowercase().as_str() {
                                "domain" => "1",
                                "private" => "2",
                                _ => "3",
                            }
                        }),
                        format!(
                            "Ensure 'Windows Firewall: {} Profile: Firewall state' is set to 'On'",
                            profile.name
                        ),
                    )]),
                );
            } else if profile.inbound_default.to_lowercase() == "allow" {
                findings.push(
                    Finding::fail(
                        format!("{}-inbound", rule_id).as_str(),
                        format!(
                            "Windows Firewall '{}' profile allows all inbound traffic by default",
                            profile.name
                        ),
                        Severity::High,
                        Category::FirewallPolicy,
                        "The firewall is enabled but configured to allow all inbound connections \
                         by default. This negates the protective effect of the firewall — only \
                         explicitly blocked ports are protected.",
                        format!("{} profile inbound default: Allow", profile.name),
                        "Block (default deny, allow exceptions)",
                        format!(
                            "Change the {} profile default inbound action to 'Block'. Allow \
                             only specific required ports via firewall rules.",
                            profile.name
                        ),
                    )
                    .with_refs(vec![ComplianceRef::cis(
                        format!("CIS WS2022 9.{}.2", {
                            match profile.name.to_lowercase().as_str() {
                                "domain" => "1",
                                "private" => "2",
                                _ => "3",
                            }
                        }),
                        format!(
                            "Ensure 'Windows Firewall: {} Profile: Inbound connections' is set to 'Block'",
                            profile.name
                        ),
                    )]),
                );
            } else {
                findings.push(Finding::pass(
                    rule_id.as_str(),
                    format!(
                        "Windows Firewall '{}' profile is enabled with default block",
                        profile.name
                    ),
                    Category::FirewallPolicy,
                ));
            }
        }

        Ok(findings)
    }
}

pub struct SmbV1Analyzer;

impl Analyzer for SmbV1Analyzer {
    fn id(&self) -> &'static str {
        "cis-18.smbv1"
    }

    fn name(&self) -> &'static str {
        "CIS §18 — SMBv1 Protocol"
    }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();

        if let Some(smb_v1) = info.security.smb_v1_enabled {
            if smb_v1 {
                findings.push(
                    Finding::fail(
                        "CIS-18.3.3",
                        "SMBv1 protocol is enabled",
                        Severity::Critical,
                        Category::NetworkSecurity,
                        "SMBv1 is a legacy protocol with multiple critical vulnerabilities, \
                         most notably exploited by the EternalBlue/WannaCry ransomware campaign. \
                         SMBv1 does not support modern security features like encryption, \
                         pre-authentication integrity, or secure dialects. There is virtually \
                         no legitimate reason to have it enabled in any modern environment.",
                        "SMBv1 enabled",
                        "SMBv1 disabled",
                        "Disable SMBv1 on Windows via PowerShell (requires reboot): \
                         Set-SmbServerConfiguration -EnableSMB1Protocol $false. \
                         Or via DISM: dism /online /norestart /disable-feature \
                         /featurename:SMB1Protocol. \
                         On Linux/Samba, set 'min protocol = SMB2' in smb.conf.",
                    )
                    .with_refs(vec![
                        ComplianceRef::cis(
                            "CIS WS2022 18.3.3",
                            "Ensure 'Configure use of passwords for fixed data drives' is set to 'Enabled'",
                        ),
                        ComplianceRef::cis(
                            "MS-L1",
                            "Disable SMBv1: Microsoft Security Advisory 2696547",
                        ),
                        ComplianceRef::nist("NIST CM-7(2)", "Least Functionality | Prevent Use of Functions/Ports/Protocols/Services"),
                    ]),
                );
            } else {
                findings.push(Finding::pass(
                    "CIS-18.3.3",
                    "SMBv1 protocol is disabled",
                    Category::NetworkSecurity,
                ));
            }
        }

        Ok(findings)
    }
}
