use crate::analyzers::{Analyzer, OsTarget};
use crate::error::HuginnError;
use crate::models::finding::{Category, ComplianceRef, Finding, Severity};
use crate::models::system_info::SystemInfo;

pub struct KernelHardeningAnalyzer;

impl Analyzer for KernelHardeningAnalyzer {
    fn id(&self) -> &'static str {
        "cis-10.kernel"
    }

    fn name(&self) -> &'static str {
        "Kernel — Hardening Parameters"
    }

    fn target_os(&self) -> OsTarget { OsTarget::Linux }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();
        let params = &info.security.kernel_params;

        if params.is_empty() {
            findings.push(Finding::skip(
                "KERNEL-HARDENING",
                "Kernel hardening parameters — data unavailable",
                "No /proc/sys parameters were collected (non-Linux platform or permission denied).",
                Category::SystemIntegrity,
            ));
            return Ok(findings);
        }

        // KERNEL-1: ASLR — randomize_va_space should be 2 (full randomization)
        match params.get("kernel/randomize_va_space").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "KERNEL-1",
                "ASLR (kernel.randomize_va_space) — not available",
                "kernel/randomize_va_space was not read from /proc/sys.",
                Category::SystemIntegrity,
            )),
            Some("2") => findings.push(Finding::pass(
                "KERNEL-1",
                "ASLR is fully enabled (randomize_va_space = 2)",
                Category::SystemIntegrity,
            )),
            Some(v) => findings.push(
                Finding::fail(
                    "KERNEL-1",
                    "ASLR is not fully enabled",
                    Severity::High,
                    Category::SystemIntegrity,
                    "Address Space Layout Randomization (ASLR) at level 2 randomizes stack, \
                     heap, and mmap addresses, making memory-corruption exploits significantly \
                     harder. Lower values reduce this protection.",
                    format!("kernel.randomize_va_space = {}", v),
                    "2",
                    "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.conf or \
                     /etc/sysctl.d/99-hardening.conf, then run 'sysctl -p'.",
                )
                .with_refs(vec![
                    ComplianceRef::cis("CIS Ubuntu 22.04 3.3.1", "Ensure address space layout randomization (ASLR) is enabled"),
                    ComplianceRef::nist("NIST SI-16", "Memory Protection"),
                ]),
            ),
        }

        // KERNEL-2: dmesg_restrict — should be 1 (restrict dmesg to root)
        match params.get("kernel/dmesg_restrict").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "KERNEL-2",
                "dmesg restriction (kernel.dmesg_restrict) — not available",
                "kernel/dmesg_restrict was not read from /proc/sys.",
                Category::SystemIntegrity,
            )),
            Some("1") => findings.push(Finding::pass(
                "KERNEL-2",
                "dmesg output is restricted to privileged users",
                Category::SystemIntegrity,
            )),
            Some(v) => findings.push(
                Finding::fail(
                    "KERNEL-2",
                    "dmesg output is not restricted",
                    Severity::Low,
                    Category::SystemIntegrity,
                    "When dmesg_restrict is 0, unprivileged users can read kernel ring buffer \
                     messages, which may expose kernel addresses and sensitive system information \
                     useful to an attacker performing local privilege escalation.",
                    format!("kernel.dmesg_restrict = {}", v),
                    "1",
                    "Set 'kernel.dmesg_restrict = 1' in /etc/sysctl.d/99-hardening.conf.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 3.3.2",
                    "Ensure kernel.dmesg_restrict is set to 1",
                )]),
            ),
        }

        // KERNEL-3: kptr_restrict — should be 2 (hide kernel pointers from all non-root)
        match params.get("kernel/kptr_restrict").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "KERNEL-3",
                "Kernel pointer restriction (kernel.kptr_restrict) — not available",
                "kernel/kptr_restrict was not read from /proc/sys.",
                Category::SystemIntegrity,
            )),
            Some("2") => findings.push(Finding::pass(
                "KERNEL-3",
                "Kernel pointer restriction is fully enabled (kptr_restrict = 2)",
                Category::SystemIntegrity,
            )),
            Some(v) => findings.push(
                Finding::fail(
                    "KERNEL-3",
                    "Kernel pointers may be exposed to unprivileged users",
                    Severity::Medium,
                    Category::SystemIntegrity,
                    "kptr_restrict controls whether kernel symbol addresses are exposed via \
                     /proc/kallsyms and similar interfaces. Values < 2 allow unprivileged users \
                     to read kernel addresses, which aids KASLR bypass and privilege escalation.",
                    format!("kernel.kptr_restrict = {}", v),
                    "2",
                    "Set 'kernel.kptr_restrict = 2' in /etc/sysctl.d/99-hardening.conf.",
                )
                .with_refs(vec![ComplianceRef::nist(
                    "NIST SI-16",
                    "Memory Protection",
                )]),
            ),
        }

        // KERNEL-4: suid_dumpable — should be 0 (no core dumps from setuid processes)
        match params.get("fs/suid_dumpable").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "KERNEL-4",
                "SUID core dump restriction (fs.suid_dumpable) — not available",
                "fs/suid_dumpable was not read from /proc/sys.",
                Category::SystemIntegrity,
            )),
            Some("0") => findings.push(Finding::pass(
                "KERNEL-4",
                "SUID core dumps are disabled",
                Category::SystemIntegrity,
            )),
            Some(v) => findings.push(
                Finding::fail(
                    "KERNEL-4",
                    "SUID processes may produce core dumps",
                    Severity::Medium,
                    Category::SystemIntegrity,
                    "When suid_dumpable is non-zero, setuid and setgid processes can produce \
                     core dumps. These dumps may contain sensitive data (passwords, keys) and \
                     can be used to recover privilege-escalation artifacts.",
                    format!("fs.suid_dumpable = {}", v),
                    "0",
                    "Set 'fs.suid_dumpable = 0' in /etc/sysctl.d/99-hardening.conf.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 1.5.4",
                    "Ensure core dumps are restricted",
                )]),
            ),
        }

        // KERNEL-5: ip_forward — should be 0 on non-router systems
        match params.get("net/ipv4/ip_forward").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "KERNEL-5",
                "IP forwarding (net.ipv4.ip_forward) — not available",
                "net/ipv4/ip_forward was not read from /proc/sys.",
                Category::NetworkSecurity,
            )),
            Some("0") => findings.push(Finding::pass(
                "KERNEL-5",
                "IPv4 packet forwarding is disabled",
                Category::NetworkSecurity,
            )),
            Some(v) => findings.push(
                Finding::fail(
                    "KERNEL-5",
                    "IPv4 packet forwarding is enabled",
                    Severity::Medium,
                    Category::NetworkSecurity,
                    "IP forwarding allows the host to route packets between network interfaces. \
                     On a non-router host, enabling this increases network attack surface and \
                     may facilitate lateral movement if the host is compromised.",
                    format!("net.ipv4.ip_forward = {}", v),
                    "0",
                    "Set 'net.ipv4.ip_forward = 0' in /etc/sysctl.d/99-hardening.conf \
                     unless this host is intentionally configured as a router.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 3.2.1",
                    "Ensure packet redirect sending is disabled",
                )]),
            ),
        }

        // KERNEL-6: tcp_syncookies — should be 1 (SYN flood protection)
        match params.get("net/ipv4/tcp_syncookies").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "KERNEL-6",
                "TCP SYN cookies (net.ipv4.tcp_syncookies) — not available",
                "net/ipv4/tcp_syncookies was not read from /proc/sys.",
                Category::NetworkSecurity,
            )),
            Some("1") => findings.push(Finding::pass(
                "KERNEL-6",
                "TCP SYN cookies are enabled (SYN flood protection active)",
                Category::NetworkSecurity,
            )),
            Some(v) => findings.push(
                Finding::fail(
                    "KERNEL-6",
                    "TCP SYN cookies are disabled",
                    Severity::Medium,
                    Category::NetworkSecurity,
                    "SYN cookies protect against SYN flood DoS attacks by allowing the server \
                     to handle connection requests without allocating state until the handshake \
                     completes. Disabling this makes the host more vulnerable to resource \
                     exhaustion attacks.",
                    format!("net.ipv4.tcp_syncookies = {}", v),
                    "1",
                    "Set 'net.ipv4.tcp_syncookies = 1' in /etc/sysctl.d/99-hardening.conf.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 3.3.8",
                    "Ensure TCP SYN Cookies is enabled",
                )]),
            ),
        }

        // KERNEL-7: accept_redirects (IPv4) — should be 0
        match params.get("net/ipv4/conf/all/accept_redirects").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "KERNEL-7",
                "IPv4 ICMP redirect acceptance — not available",
                "net/ipv4/conf/all/accept_redirects was not read from /proc/sys.",
                Category::NetworkSecurity,
            )),
            Some("0") => findings.push(Finding::pass(
                "KERNEL-7",
                "IPv4 ICMP redirect acceptance is disabled",
                Category::NetworkSecurity,
            )),
            Some(v) => findings.push(
                Finding::fail(
                    "KERNEL-7",
                    "IPv4 ICMP redirects are accepted",
                    Severity::Medium,
                    Category::NetworkSecurity,
                    "Accepting ICMP redirects allows remote hosts to modify the local routing \
                     table, which can be abused for man-in-the-middle attacks by redirecting \
                     traffic through an attacker-controlled gateway.",
                    format!("net.ipv4.conf.all.accept_redirects = {}", v),
                    "0",
                    "Set 'net.ipv4.conf.all.accept_redirects = 0' in /etc/sysctl.d/99-hardening.conf.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 3.3.2",
                    "Ensure ICMP redirects are not accepted",
                )]),
            ),
        }

        // KERNEL-8: accept_source_route — should be 0
        match params.get("net/ipv4/conf/all/accept_source_route").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "KERNEL-8",
                "IPv4 source routing — not available",
                "net/ipv4/conf/all/accept_source_route was not read from /proc/sys.",
                Category::NetworkSecurity,
            )),
            Some("0") => findings.push(Finding::pass(
                "KERNEL-8",
                "IPv4 source routing is disabled",
                Category::NetworkSecurity,
            )),
            Some(v) => findings.push(
                Finding::fail(
                    "KERNEL-8",
                    "IPv4 source-routed packets are accepted",
                    Severity::Medium,
                    Category::NetworkSecurity,
                    "Source routing allows the sender to specify the network path for packets. \
                     This can be abused to bypass network access controls and facilitate \
                     spoofing or man-in-the-middle attacks.",
                    format!("net.ipv4.conf.all.accept_source_route = {}", v),
                    "0",
                    "Set 'net.ipv4.conf.all.accept_source_route = 0' in /etc/sysctl.d/99-hardening.conf.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 3.3.1",
                    "Ensure source routed packets are not accepted",
                )]),
            ),
        }

        // KERNEL-9: log_martians — should be 1
        match params.get("net/ipv4/conf/all/log_martians").map(|s| s.as_str()) {
            None => findings.push(Finding::skip(
                "KERNEL-9",
                "Martian packet logging — not available",
                "net/ipv4/conf/all/log_martians was not read from /proc/sys.",
                Category::NetworkSecurity,
            )),
            Some("1") => findings.push(Finding::pass(
                "KERNEL-9",
                "Logging of packets with impossible addresses (martians) is enabled",
                Category::NetworkSecurity,
            )),
            Some(v) => findings.push(
                Finding::fail(
                    "KERNEL-9",
                    "Martian packet logging is disabled",
                    Severity::Low,
                    Category::NetworkSecurity,
                    "Martian packets have source addresses that are impossible on the public \
                     internet (RFC 1918, loopback, etc. arriving on external interfaces). \
                     Logging these aids detection of spoofing and scanning attempts.",
                    format!("net.ipv4.conf.all.log_martians = {}", v),
                    "1",
                    "Set 'net.ipv4.conf.all.log_martians = 1' in /etc/sysctl.d/99-hardening.conf.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 3.3.7",
                    "Ensure Reverse Path Filtering is enabled",
                )]),
            ),
        }

        // KERNEL-10: rp_filter — should be 1 or 2 (reverse path filtering)
        match params.get("net/ipv4/conf/all/rp_filter").and_then(|v| v.parse::<u32>().ok()) {
            None => findings.push(Finding::skip(
                "KERNEL-10",
                "Reverse path filtering (net.ipv4.conf.all.rp_filter) — not available",
                "net/ipv4/conf/all/rp_filter was not read from /proc/sys.",
                Category::NetworkSecurity,
            )),
            Some(n) if n >= 1 => findings.push(Finding::pass(
                "KERNEL-10",
                "Reverse path filtering is enabled",
                Category::NetworkSecurity,
            )),
            Some(n) => findings.push(
                Finding::fail(
                    "KERNEL-10",
                    "Reverse path filtering is disabled",
                    Severity::Medium,
                    Category::NetworkSecurity,
                    "Reverse path filtering validates that incoming packets have a source \
                     address reachable via the interface they arrived on. Disabling it allows \
                     IP spoofing attacks to bypass basic network-layer controls.",
                    format!("net.ipv4.conf.all.rp_filter = {}", n),
                    "1 or 2",
                    "Set 'net.ipv4.conf.all.rp_filter = 1' in /etc/sysctl.d/99-hardening.conf.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS Ubuntu 22.04 3.3.7",
                    "Ensure Reverse Path Filtering is enabled",
                )]),
            ),
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::Analyzer;
    use crate::models::finding::Severity;
    use crate::models::system_info::SystemInfo;

    fn info_with_params(params: &[(&str, &str)]) -> SystemInfo {
        let mut info = SystemInfo::default();
        info.security.kernel_params = params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        info
    }

    #[test]
    fn empty_kernel_params_skips() {
        let findings = KernelHardeningAnalyzer.analyze(&SystemInfo::default()).unwrap();
        assert!(findings.iter().any(|f| f.skipped && f.rule_id == "KERNEL-HARDENING"));
    }

    #[test]
    fn aslr_not_2_fails_high() {
        let info = info_with_params(&[("kernel/randomize_va_space", "0")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-1").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn aslr_2_passes() {
        let info = info_with_params(&[("kernel/randomize_va_space", "2")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-1").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn dmesg_restrict_0_fails_low() {
        let info = info_with_params(&[("kernel/dmesg_restrict", "0")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-2").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn dmesg_restrict_1_passes() {
        let info = info_with_params(&[("kernel/dmesg_restrict", "1")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-2").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn kptr_restrict_not_2_fails_medium() {
        let info = info_with_params(&[("kernel/kptr_restrict", "0")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-3").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn ip_forward_enabled_fails_medium() {
        let info = info_with_params(&[("net/ipv4/ip_forward", "1")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-5").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn ip_forward_disabled_passes() {
        let info = info_with_params(&[("net/ipv4/ip_forward", "0")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-5").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn tcp_syncookies_disabled_fails_medium() {
        let info = info_with_params(&[("net/ipv4/tcp_syncookies", "0")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-6").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn rp_filter_0_fails_medium() {
        let info = info_with_params(&[("net/ipv4/conf/all/rp_filter", "0")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-10").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn rp_filter_1_passes() {
        let info = info_with_params(&[("net/ipv4/conf/all/rp_filter", "1")]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "KERNEL-10").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn fully_hardened_kernel_all_pass() {
        let info = info_with_params(&[
            ("kernel/randomize_va_space", "2"),
            ("kernel/dmesg_restrict", "1"),
            ("kernel/kptr_restrict", "2"),
            ("fs/suid_dumpable", "0"),
            ("net/ipv4/ip_forward", "0"),
            ("net/ipv4/tcp_syncookies", "1"),
            ("net/ipv4/conf/all/accept_redirects", "0"),
            ("net/ipv4/conf/all/accept_source_route", "0"),
            ("net/ipv4/conf/all/log_martians", "1"),
            ("net/ipv4/conf/all/rp_filter", "1"),
        ]);
        let findings = KernelHardeningAnalyzer.analyze(&info).unwrap();
        assert!(findings.iter().all(|f| f.passed || f.skipped));
    }
}
