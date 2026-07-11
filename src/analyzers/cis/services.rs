use crate::analyzers::{Analyzer, OsTarget};
use crate::error::HuginnError;
use crate::models::finding::{Category, ComplianceRef, Finding, Severity};
use crate::models::system_info::SystemInfo;

pub struct UnquotedServicePathAnalyzer;

impl Analyzer for UnquotedServicePathAnalyzer {
    fn id(&self) -> &'static str {
        "cis-5.svc.unquoted"
    }

    fn name(&self) -> &'static str {
        "Service — Unquoted Binary Paths"
    }

    fn target_os(&self) -> OsTarget { OsTarget::Windows }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();
        let services = &info.services.services;

        if services.is_empty() {
            findings.push(Finding::skip(
                "SVC-UNQUOTED-PATH",
                "Unquoted service paths — data unavailable",
                "No service data was collected. Re-run with elevated privileges to enumerate services.",
                Category::ServiceSecurity,
            ));
            return Ok(findings);
        }

        let mut flagged = 0;
        for svc in services {
            if !svc.unquoted_path {
                continue;
            }
            flagged += 1;
            let path = svc.binary_path.as_deref().unwrap_or("unknown");
            findings.push(
                Finding::fail(
                    "SVC-UNQUOTED-PATH",
                    format!("Service '{}' has an unquoted binary path with spaces", svc.display_name),
                    Severity::Medium,
                    Category::ServiceSecurity,
                    "When a service binary path contains spaces and is not quoted, Windows \
                     will attempt to execute each space-separated segment as a potential binary \
                     path before reaching the real one. An attacker who can write to an \
                     intermediate directory can place a malicious binary that runs as SYSTEM.",
                    format!("Unquoted path: {}", path),
                    "Quoted path: \"C:\\Path With Spaces\\service.exe\"",
                    format!(
                        "Wrap the binary path in double quotes for service '{}'. \
                         Modify via: sc config \"{}\" binpath= \"\\\"{}\\\"\"",
                        svc.name, svc.name, path
                    ),
                )
                .with_refs(vec![ComplianceRef::nist(
                    "NIST CM-7",
                    "Least Functionality",
                )])
                .with_evidence(format!("Service: {} | Path: {}", svc.name, path)),
            );
        }

        if flagged == 0 {
            findings.push(Finding::pass(
                "SVC-UNQUOTED-PATH",
                "No services with unquoted binary paths detected",
                Category::ServiceSecurity,
            ));
        }

        Ok(findings)
    }
}

pub struct WeakServicePermissionsAnalyzer;

impl Analyzer for WeakServicePermissionsAnalyzer {
    fn id(&self) -> &'static str {
        "cis-5.svc.permissions"
    }

    fn name(&self) -> &'static str {
        "Service — Weak Binary Permissions"
    }

    fn target_os(&self) -> OsTarget { OsTarget::Windows }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();
        let services = &info.services.services;

        if services.is_empty() {
            findings.push(Finding::skip(
                "SVC-WEAK-PERMS",
                "Service binary permissions — data unavailable",
                "No service data was collected. Re-run with elevated privileges to enumerate services.",
                Category::ServiceSecurity,
            ));
            return Ok(findings);
        }

        let mut flagged = 0;
        for svc in services {
            if !svc.weak_permissions {
                continue;
            }
            flagged += 1;
            let path = svc.binary_path.as_deref().unwrap_or("unknown");
            findings.push(
                Finding::fail(
                    "SVC-WEAK-PERMS",
                    format!(
                        "Service '{}' binary has weak permissions (world-writable)",
                        svc.display_name
                    ),
                    Severity::High,
                    Category::ServiceSecurity,
                    "A service binary or its parent directory is writable by non-administrative \
                     users. An attacker with local user access can replace the binary with \
                     a malicious executable that runs with the service's privileges (often SYSTEM).",
                    format!("Weak ACL on: {}", path),
                    "Only SYSTEM and Administrators have write access",
                    format!(
                        "Restrict write permissions on '{}' and its parent directories to \
                         SYSTEM and Administrators only. Use icacls to inspect and fix: \
                         icacls \"{}\" /inheritance:d /grant:r \"SYSTEM:(F)\" \
                         \"Administrators:(F)\"",
                        path, path
                    ),
                )
                .with_refs(vec![
                    ComplianceRef::cis("CIS WS2022 5.x", "Ensure service binary ACLs are configured correctly"),
                    ComplianceRef::nist("NIST CM-6", "Configuration Settings"),
                ])
                .with_evidence(format!("Service: {} | Binary: {}", svc.name, path)),
            );
        }

        if flagged == 0 {
            findings.push(Finding::pass(
                "SVC-WEAK-PERMS",
                "No services with weak binary permissions detected",
                Category::ServiceSecurity,
            ));
        }

        Ok(findings)
    }
}
