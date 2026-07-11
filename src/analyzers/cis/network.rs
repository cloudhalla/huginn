use crate::analyzers::{Analyzer, OsTarget};
use crate::error::HuginnError;
use crate::models::finding::{Category, ComplianceRef, Finding, Severity};
use crate::models::system_info::SystemInfo;

// ── Windows Firewall ──────────────────────────────────────────────

pub struct WindowsFirewallAnalyzer;

impl Analyzer for WindowsFirewallAnalyzer {
    fn id(&self) -> &'static str {
        "cis-9.fw"
    }

    fn name(&self) -> &'static str {
        "CIS §9 — Windows Firewall"
    }

    fn target_os(&self) -> OsTarget { OsTarget::Windows }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();

        if info.network.firewall_profiles.is_empty() {
            findings.push(Finding::skip(
                "CIS-9.0",
                "Windows Firewall status — data unavailable",
                "Unable to retrieve Windows Firewall profile data. The tool may lack elevated \
                 privileges or the Windows Firewall service is not running.",
                Category::FirewallPolicy,
            ));
            return Ok(findings);
        }

        for profile in &info.network.firewall_profiles {
            let rule_id = format!("CIS-9.{}", profile.name.to_lowercase().replace(' ', "-"));
            let cis_section = match profile.name.to_lowercase().as_str() {
                "domain"  => "9.1",
                "private" => "9.2",
                _         => "9.3",
            };

            if !profile.enabled {
                let severity = if profile.name.to_lowercase().contains("public") {
                    Severity::Critical
                } else {
                    Severity::High
                };
                findings.push(
                    Finding::fail(
                        rule_id.as_str(),
                        format!("Windows Firewall '{}' profile is disabled", profile.name),
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
                            "Enable the {} firewall profile via Windows Defender Firewall with \
                             Advanced Security, or via Group Policy: Computer Configuration > \
                             Windows Settings > Security Settings > Windows Defender Firewall with \
                             Advanced Security > Windows Defender Firewall Properties > {} Profile \
                             > Firewall state: On.",
                            profile.name, profile.name
                        ),
                    )
                    .with_refs(vec![ComplianceRef::cis(
                        format!("CIS WS2022 {}.1", cis_section),
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
                             only specific required ports via inbound firewall rules.",
                            profile.name
                        ),
                    )
                    .with_refs(vec![ComplianceRef::cis(
                        format!("CIS WS2022 {}.2", cis_section),
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
                        "Windows Firewall '{}' profile is enabled with default-deny inbound",
                        profile.name
                    ),
                    Category::FirewallPolicy,
                ));
            }
        }

        Ok(findings)
    }
}

// ── Linux Host Firewall ───────────────────────────────────────────

pub struct LinuxFirewallAnalyzer;

impl Analyzer for LinuxFirewallAnalyzer {
    fn id(&self) -> &'static str {
        "cis-3.5.fw"
    }

    fn name(&self) -> &'static str {
        "CIS §3.5 — Host Firewall"
    }

    fn target_os(&self) -> OsTarget { OsTarget::Linux }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();

        if info.network.firewall_profiles.is_empty() {
            findings.push(Finding::skip(
                "FW-1",
                "Host firewall status — no firewall tool detected",
                "Neither ufw nor iptables was found or accessible. Install and enable a host \
                 firewall to control inbound and outbound traffic.",
                Category::FirewallPolicy,
            ));
            return Ok(findings);
        }

        for profile in &info.network.firewall_profiles {
            match profile.name.as_str() {
                "ufw" => {
                    if profile.enabled {
                        findings.push(Finding::pass(
                            "FW-1",
                            "Host firewall (ufw) is active",
                            Category::FirewallPolicy,
                        ));
                    } else {
                        findings.push(
                            Finding::fail(
                                "FW-1",
                                "Host firewall (ufw) is inactive",
                                Severity::Critical,
                                Category::FirewallPolicy,
                                "ufw is installed but not active, leaving all ports open by \
                                 default. Without a host firewall, any service bound to a \
                                 network interface is reachable from the network.",
                                "ufw status: inactive",
                                "ufw status: active",
                                "Enable ufw with: 'ufw enable'. Before enabling, ensure you have \
                                 a rule allowing SSH to avoid locking yourself out: \
                                 'ufw allow ssh && ufw enable'.",
                            )
                            .with_refs(vec![
                                ComplianceRef::cis(
                                    "CIS Ubuntu 22.04 3.5.1.1",
                                    "Ensure ufw is installed",
                                ),
                                ComplianceRef::cis(
                                    "CIS Ubuntu 22.04 3.5.1.2",
                                    "Ensure iptables-persistent is not installed with ufw",
                                ),
                                ComplianceRef::nist(
                                    "NIST SC-7",
                                    "Boundary Protection",
                                ),
                            ]),
                        );
                    }
                }
                "iptables" => {
                    if profile.enabled {
                        findings.push(Finding::pass(
                            "FW-2",
                            "Host firewall (iptables) has active rules",
                            Category::FirewallPolicy,
                        ));
                    } else {
                        findings.push(
                            Finding::fail(
                                "FW-2",
                                "Host firewall (iptables) has no active rules",
                                Severity::High,
                                Category::FirewallPolicy,
                                "iptables is present but no rules have been configured. \
                                 The default policy likely accepts all traffic, providing no \
                                 network-level protection.",
                                "iptables: no rules configured",
                                "Active inbound deny-by-default policy",
                                "Configure iptables rules to deny inbound traffic by default \
                                 and allow only required ports. Consider using ufw or nftables \
                                 for simpler management: 'apt install ufw && ufw enable'.",
                            )
                            .with_refs(vec![
                                ComplianceRef::cis(
                                    "CIS Ubuntu 22.04 3.5.2.1",
                                    "Ensure iptables are flushed with nftables",
                                ),
                                ComplianceRef::nist(
                                    "NIST SC-7",
                                    "Boundary Protection",
                                ),
                            ]),
                        );
                    }
                }
                other => {
                    if profile.enabled {
                        findings.push(Finding::pass(
                            format!("FW-{}", other).as_str(),
                            format!("Host firewall ({}) is active", other),
                            Category::FirewallPolicy,
                        ));
                    } else {
                        findings.push(
                            Finding::fail(
                                format!("FW-{}", other).as_str(),
                                format!("Host firewall ({}) is inactive", other),
                                Severity::High,
                                Category::FirewallPolicy,
                                format!(
                                    "The {} firewall is installed but not active, \
                                     leaving the host without network-level protection.",
                                    other
                                ),
                                format!("{}: inactive", other),
                                "Active with default-deny inbound",
                                format!("Enable the {} firewall and configure a default-deny inbound policy.", other),
                            )
                            .with_refs(vec![ComplianceRef::nist("NIST SC-7", "Boundary Protection")]),
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}

// ── SMBv1 ────────────────────────────────────────────────────────

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

        match info.security.smb_v1_enabled {
            None => findings.push(Finding::skip(
                "CIS-18.3.3",
                "SMBv1 protocol status — data unavailable",
                "Unable to determine SMBv1 status. On Linux, this requires \
                 /etc/samba/smb.conf; on Windows, registry or PowerShell access is needed.",
                Category::NetworkSecurity,
            )),
            Some(true) => findings.push(
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
                    if std::env::consts::OS == "windows" {
                        "Disable SMBv1 via PowerShell (requires reboot): \
                         Set-SmbServerConfiguration -EnableSMB1Protocol $false. \
                         Or via DISM: dism /online /norestart /disable-feature \
                         /featurename:SMB1Protocol."
                    } else {
                        "Disable SMBv1 in Samba by setting 'min protocol = SMB2' \
                         in /etc/samba/smb.conf, then restart smbd: \
                         'systemctl restart smbd'."
                    },
                )
                .with_refs(vec![
                    ComplianceRef::cis(
                        if std::env::consts::OS == "windows" { "CIS WS2022 18.3.3" } else { "CIS Ubuntu 22.04" },
                        "Disable SMBv1: Microsoft Security Advisory 2696547",
                    ),
                    ComplianceRef::nist("NIST CM-7(2)", "Least Functionality | Prevent Use of Functions/Ports/Protocols/Services"),
                ]),
            ),
            Some(false) => findings.push(Finding::pass(
                "CIS-18.3.3",
                "SMBv1 protocol is disabled",
                Category::NetworkSecurity,
            )),
        }

        Ok(findings)
    }
}
