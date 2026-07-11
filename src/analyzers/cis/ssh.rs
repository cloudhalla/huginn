use crate::analyzers::{Analyzer, OsTarget};
use crate::error::HuginnError;
use crate::models::finding::{Category, ComplianceRef, Finding, Severity};
use crate::models::system_info::SystemInfo;

pub struct SshHardeningAnalyzer;

impl Analyzer for SshHardeningAnalyzer {
    fn id(&self) -> &'static str {
        "cis-9.ssh"
    }

    fn name(&self) -> &'static str {
        "SSH — Server Hardening"
    }

    fn target_os(&self) -> OsTarget { OsTarget::Linux }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();
        let cfg = &info.security.ssh_config;

        if cfg.is_empty() {
            findings.push(Finding::skip(
                "SSH-HARDENING",
                "SSH server configuration — data unavailable",
                "No sshd_config file was found or the SSH daemon is not installed.",
                Category::NetworkSecurity,
            ));
            return Ok(findings);
        }

        // SSH-1: PermitRootLogin must not be 'yes'
        match cfg.get("permitrootlogin").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "SSH-1",
                "SSH PermitRootLogin — not configured",
                "PermitRootLogin directive is absent from sshd_config; sshd will use its compiled-in default.",
                Category::NetworkSecurity,
            )),
            Some("yes") => findings.push(
                Finding::fail(
                    "SSH-1",
                    "SSH allows root login with password",
                    Severity::Critical,
                    Category::NetworkSecurity,
                    "PermitRootLogin yes allows direct SSH login as root. A successful brute-force \
                     or credential-stuffing attack immediately yields full system access.",
                    "PermitRootLogin yes",
                    "no or prohibit-password",
                    "Set 'PermitRootLogin no' (or 'prohibit-password' to allow key-only root login) \
                     in /etc/ssh/sshd_config, then run 'systemctl restart sshd'.",
                )
                .with_refs(vec![
                    ComplianceRef::cis("CIS Ubuntu 22.04 5.2.7", "Ensure SSH root login is disabled"),
                    ComplianceRef::nist("NIST AC-6(9)", "Least Privilege | Log Use of Privileged Functions"),
                ]),
            ),
            Some(v) if v == "prohibit-password" || v == "without-password" => findings.push(Finding::pass(
                "SSH-1",
                "SSH root login restricted to key-based authentication",
                Category::NetworkSecurity,
            )),
            Some("no") => findings.push(Finding::pass(
                "SSH-1",
                "SSH root login is disabled",
                Category::NetworkSecurity,
            )),
            Some(other) => findings.push(
                Finding::fail(
                    "SSH-1",
                    "SSH PermitRootLogin has an unexpected value",
                    Severity::Medium,
                    Category::NetworkSecurity,
                    "The PermitRootLogin value is non-standard; verify it restricts root access.",
                    format!("PermitRootLogin {}", other),
                    "no or prohibit-password",
                    "Set 'PermitRootLogin no' in /etc/ssh/sshd_config.",
                ),
            ),
        }

        // SSH-2: PasswordAuthentication must be 'no'
        match cfg.get("passwordauthentication").map(|s| s.as_str()) {
            None | Some("yes") => findings.push(
                Finding::fail(
                    "SSH-2",
                    "SSH allows password-based authentication",
                    Severity::High,
                    Category::NetworkSecurity,
                    "Password authentication over SSH exposes the system to brute-force and \
                     credential-stuffing attacks. Key-based authentication is significantly \
                     more resistant to remote compromise.",
                    cfg.get("passwordauthentication")
                        .map(|v| format!("PasswordAuthentication {}", v))
                        .unwrap_or_else(|| "PasswordAuthentication yes (default)".into()),
                    "PasswordAuthentication no",
                    "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and ensure all \
                     users have SSH keys configured before disabling. Restart sshd afterward.",
                )
                .with_refs(vec![
                    ComplianceRef::cis("CIS Ubuntu 22.04 5.2.11", "Ensure SSH PasswordAuthentication is disabled"),
                    ComplianceRef::nist("NIST IA-2(1)", "Identification and Authentication | Multi-Factor Authentication"),
                ]),
            ),
            Some("no") => findings.push(Finding::pass(
                "SSH-2",
                "SSH password authentication is disabled (key-based only)",
                Category::NetworkSecurity,
            )),
            _ => {}
        }

        // SSH-3: PermitEmptyPasswords must be 'no'
        match cfg.get("permitemptypasswords").map(|s| s.as_str()) {
            None | Some("no") => findings.push(Finding::pass(
                "SSH-3",
                "SSH empty password authentication is disabled",
                Category::NetworkSecurity,
            )),
            Some("yes") => findings.push(
                Finding::fail(
                    "SSH-3",
                    "SSH permits login with empty passwords",
                    Severity::Critical,
                    Category::NetworkSecurity,
                    "Allowing empty passwords means any account without a password set can \
                     be accessed over SSH with no credentials at all.",
                    "PermitEmptyPasswords yes",
                    "PermitEmptyPasswords no",
                    "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 5.2.9",
                    "Ensure SSH PermitEmptyPasswords is disabled",
                )]),
            ),
            _ => {}
        }

        // SSH-4: X11Forwarding should be 'no'
        match cfg.get("x11forwarding").map(|s| s.as_str()) {
            None | Some("no") => findings.push(Finding::pass(
                "SSH-4",
                "SSH X11 forwarding is disabled",
                Category::NetworkSecurity,
            )),
            Some("yes") => findings.push(
                Finding::fail(
                    "SSH-4",
                    "SSH X11 forwarding is enabled",
                    Severity::Low,
                    Category::NetworkSecurity,
                    "X11 forwarding allows clients to display graphical applications through \
                     the SSH tunnel. If not required, disabling it reduces attack surface — \
                     a compromised client could inject X11 events into the server's display.",
                    "X11Forwarding yes",
                    "X11Forwarding no",
                    "Set 'X11Forwarding no' in /etc/ssh/sshd_config unless X11 tunneling is \
                     a documented requirement.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 5.2.6",
                    "Ensure SSH X11 forwarding is disabled",
                )]),
            ),
            _ => {}
        }

        // SSH-5: MaxAuthTries <= 4
        match cfg.get("maxauthtries").and_then(|v| v.parse::<u32>().ok()) {
            None => findings.push(Finding::skip(
                "SSH-5",
                "SSH MaxAuthTries — not configured",
                "MaxAuthTries is absent from sshd_config; sshd will use its compiled-in default (6).",
                Category::NetworkSecurity,
            )),
            Some(n) if n > 4 => findings.push(
                Finding::fail(
                    "SSH-5",
                    "SSH MaxAuthTries is higher than recommended",
                    Severity::Low,
                    Category::NetworkSecurity,
                    "A high MaxAuthTries allows more authentication attempts per connection, \
                     making slow brute-force attacks more practical.",
                    format!("MaxAuthTries {}", n),
                    "4 or fewer",
                    "Set 'MaxAuthTries 4' (or lower) in /etc/ssh/sshd_config.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 5.2.8",
                    "Ensure SSH MaxAuthTries is set to 4 or less",
                )]),
            ),
            Some(_) => findings.push(Finding::pass(
                "SSH-5",
                "SSH MaxAuthTries is within recommended limit",
                Category::NetworkSecurity,
            )),
        }

        // SSH-6: UsePAM should be 'yes' (ensures PAM policies apply to SSH)
        match cfg.get("usepam").map(|s| s.as_str()) {
            None | Some("yes") => findings.push(Finding::pass(
                "SSH-6",
                "SSH PAM integration is enabled",
                Category::NetworkSecurity,
            )),
            Some("no") => findings.push(
                Finding::fail(
                    "SSH-6",
                    "SSH PAM integration is disabled",
                    Severity::Medium,
                    Category::NetworkSecurity,
                    "With UsePAM no, SSH bypasses PAM account and session management. \
                     This means account lockout policies, MFA modules, and access controls \
                     configured in PAM may not apply to SSH sessions.",
                    "UsePAM no",
                    "UsePAM yes",
                    "Set 'UsePAM yes' in /etc/ssh/sshd_config to ensure PAM policies \
                     (lockout, MFA, session logging) are enforced for SSH sessions.",
                )
                .with_refs(vec![ComplianceRef::nist(
                    "NIST IA-2",
                    "Identification and Authentication (Organizational Users)",
                )]),
            ),
            _ => {}
        }

        Ok(findings)
    }
}
