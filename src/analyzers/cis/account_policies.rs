use crate::analyzers::Analyzer;
use crate::error::HuginnError;
use crate::models::finding::{Category, ComplianceRef, Finding, Severity};
use crate::models::system_info::SystemInfo;

pub struct PasswordPolicyAnalyzer;

impl Analyzer for PasswordPolicyAnalyzer {
    fn id(&self) -> &'static str {
        "cis-1.1"
    }

    fn name(&self) -> &'static str {
        "CIS §1.1 — Password Policy"
    }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();
        let policy = &info.users.password_policy;

        // CIS 1.1.1 — Minimum password length >= 14
        match policy.min_length {
            None => findings.push(Finding::skip(
                "CIS-1.1.1",
                "Minimum password length — data unavailable",
                "Password policy data could not be collected on this platform.",
                Category::AccountPolicy,
            )),
            Some(min_len) if min_len < 14 => findings.push(
                Finding::fail(
                    "CIS-1.1.1",
                    "Minimum password length is below recommended threshold",
                    Severity::High,
                    Category::AccountPolicy,
                    "Short passwords are easily brute-forced. CIS Benchmark Level 1 requires \
                     a minimum of 14 characters to meaningfully resist offline attacks.",
                    format!("{} characters", min_len),
                    "14 or more characters",
                    "Set 'Minimum password length' to 14 or greater. On Windows: \
                     Computer Configuration > Windows Settings > Security Settings > \
                     Account Policies > Password Policy. On Linux: edit \
                     /etc/security/pwquality.conf and set minlen = 14.",
                )
                .with_refs(vec![
                    ComplianceRef::cis(
                        "CIS WS2022 1.1.1",
                        "Ensure 'Minimum password length' is set to '14 or more character(s)'",
                    ),
                    ComplianceRef::nist("NIST IA-5(1)", "Authenticator Management | Password-Based Authentication"),
                ]),
            ),
            Some(_) => findings.push(Finding::pass(
                "CIS-1.1.1",
                "Minimum password length meets recommended threshold",
                Category::AccountPolicy,
            )),
        }

        // CIS 1.1.2 — Maximum password age <= 365 days (and not 0 = never expires)
        match policy.max_age_days {
            None => findings.push(Finding::skip(
                "CIS-1.1.2",
                "Maximum password age — data unavailable",
                "Password policy data could not be collected on this platform.",
                Category::AccountPolicy,
            )),
            Some(0) => findings.push(
                Finding::fail(
                    "CIS-1.1.2",
                    "Passwords are set to never expire",
                    Severity::Medium,
                    Category::AccountPolicy,
                    "When passwords never expire, compromised credentials can be used \
                     indefinitely. CIS recommends a maximum age of 365 days or less.",
                    "Passwords never expire (0)",
                    "1-365 days",
                    "Set 'Maximum password age' to 365 days or fewer. Never set to 0 \
                     (never expires) for standard accounts.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS WS2022 1.1.2",
                    "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
                )]),
            ),
            Some(max_age) if max_age > 365 => findings.push(
                Finding::fail(
                    "CIS-1.1.2",
                    "Maximum password age exceeds recommended limit",
                    Severity::Low,
                    Category::AccountPolicy,
                    "Passwords that age beyond 365 days increase exposure from credential \
                     compromise going undetected.",
                    format!("{} days", max_age),
                    "365 days or fewer",
                    "Set 'Maximum password age' to 365 days or fewer.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS WS2022 1.1.2",
                    "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
                )]),
            ),
            Some(_) => findings.push(Finding::pass(
                "CIS-1.1.2",
                "Maximum password age is within recommended range",
                Category::AccountPolicy,
            )),
        }

        // CIS 1.1.3 — Password history >= 24
        match policy.history_count {
            None => findings.push(Finding::skip(
                "CIS-1.1.3",
                "Password history count — data unavailable",
                "Password policy data could not be collected on this platform.",
                Category::AccountPolicy,
            )),
            Some(history) if history < 24 => findings.push(
                Finding::fail(
                    "CIS-1.1.3",
                    "Password history count is below recommended minimum",
                    Severity::Medium,
                    Category::AccountPolicy,
                    "A low password history count allows users to cycle through a small \
                     number of passwords and quickly reuse old ones, negating rotation policies.",
                    format!("{} passwords remembered", history),
                    "24 or more passwords",
                    "Set 'Enforce password history' to 24 or more. On Windows: \
                     Computer Configuration > Windows Settings > Security Settings > \
                     Account Policies > Password Policy.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS WS2022 1.1.3",
                    "Ensure 'Enforce password history' is set to '24 or more password(s)'",
                )]),
            ),
            Some(_) => findings.push(Finding::pass(
                "CIS-1.1.3",
                "Password history count meets recommended minimum",
                Category::AccountPolicy,
            )),
        }

        // CIS 1.1.4 — Password complexity required
        match policy.complexity_required {
            None => findings.push(Finding::skip(
                "CIS-1.1.4",
                "Password complexity requirements — data unavailable",
                "Password complexity setting could not be collected. On Windows, this value \
                 lives in the local security policy and typically requires administrator \
                 privileges to read (via `secedit /export`). Re-run huginn from an elevated \
                 prompt to include this check.",
                Category::AccountPolicy,
            )),
            Some(false) => findings.push(
                Finding::fail(
                    "CIS-1.1.4",
                    "Password complexity requirements are disabled",
                    Severity::High,
                    Category::AccountPolicy,
                    "Without complexity requirements, users can set trivially guessable \
                     passwords. Complexity requirements ensure passwords contain a mix of \
                     character types.",
                    "Disabled",
                    "Enabled",
                    "Enable 'Password must meet complexity requirements'. On Windows: \
                     Computer Configuration > Windows Settings > Security Settings > \
                     Account Policies > Password Policy. On Linux: configure pam_pwquality \
                     with dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS WS2022 1.1.4",
                    "Ensure 'Password must meet complexity requirements' is set to 'Enabled'",
                )]),
            ),
            Some(true) => findings.push(Finding::pass(
                "CIS-1.1.4",
                "Password complexity requirements are enabled",
                Category::AccountPolicy,
            )),
        }

        // CIS 1.1.5 — Reversible encryption disabled (Windows only, skip silently on Linux)
        if std::env::consts::OS == "windows" { match policy.reversible_encryption {
            None => findings.push(Finding::skip(
                "CIS-1.1.5",
                "Reversible password encryption — data unavailable",
                "Reversible-encryption setting could not be collected. On Windows, this value \
                 lives in the local security policy and typically requires administrator \
                 privileges to read (via `secedit /export`). Re-run huginn from an elevated \
                 prompt to include this check.",
                Category::AccountPolicy,
            )),
            Some(true) => findings.push(
                Finding::fail(
                    "CIS-1.1.5",
                    "Passwords stored with reversible encryption",
                    Severity::Critical,
                    Category::AccountPolicy,
                    "Storing passwords with reversible encryption is essentially the same \
                     as storing them in plaintext. This setting should never be enabled in \
                     production environments.",
                    "Enabled",
                    "Disabled",
                    "Disable 'Store passwords using reversible encryption'. This setting \
                     should only ever be enabled for specific legacy application compatibility \
                     and disabled immediately after.",
                )
                .with_refs(vec![
                    ComplianceRef::cis(
                        "CIS WS2022 1.1.5",
                        "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'",
                    ),
                    ComplianceRef::nist("NIST IA-5(1)(c)", "Authenticator Management | Encrypted Transmission"),
                ]),
            ),
            Some(false) => findings.push(Finding::pass(
                "CIS-1.1.5",
                "Reversible password encryption is disabled",
                Category::AccountPolicy,
            )),
        } } // end match + if windows

        Ok(findings)
    }
}

pub struct LockoutPolicyAnalyzer;

impl Analyzer for LockoutPolicyAnalyzer {
    fn id(&self) -> &'static str {
        "cis-1.2"
    }

    fn name(&self) -> &'static str {
        "CIS §1.2 — Account Lockout Policy"
    }

    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError> {
        let mut findings = Vec::new();
        let policy = &info.users.lockout_policy;

        // CIS 1.2.1 — Account lockout threshold <= 5 (and not 0 = never locks)
        match policy.threshold {
            None => findings.push(Finding::skip(
                "CIS-1.2.1",
                "Account lockout threshold — data unavailable",
                "Lockout policy data could not be collected on this platform.",
                Category::AccountPolicy,
            )),
            Some(0) => findings.push(
                Finding::fail(
                    "CIS-1.2.1",
                    "Account lockout is disabled (threshold set to 0)",
                    Severity::High,
                    Category::AccountPolicy,
                    "With no account lockout threshold, an attacker can attempt unlimited \
                     password guesses without being locked out, enabling unlimited brute-force \
                     attacks against local accounts.",
                    "0 (never locks out)",
                    "5 or fewer invalid attempts",
                    "Set 'Account lockout threshold' to 5 or fewer invalid login attempts. \
                     This limits brute-force attack windows.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS WS2022 1.2.1",
                    "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'",
                )]),
            ),
            Some(threshold) if threshold > 5 => findings.push(
                Finding::fail(
                    "CIS-1.2.1",
                    "Account lockout threshold exceeds recommended maximum",
                    Severity::Medium,
                    Category::AccountPolicy,
                    "A high lockout threshold allows more brute-force attempts before locking \
                     out an account, increasing the attack surface.",
                    format!("{} invalid attempts", threshold),
                    "5 or fewer invalid attempts",
                    "Set 'Account lockout threshold' to 5 or fewer invalid login attempts.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS WS2022 1.2.1",
                    "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'",
                )]),
            ),
            Some(_) => findings.push(Finding::pass(
                "CIS-1.2.1",
                "Account lockout threshold is within recommended range",
                Category::AccountPolicy,
            )),
        }

        // CIS 1.2.2 — Account lockout duration >= 15 minutes
        match policy.duration_minutes {
            None => findings.push(Finding::skip(
                "CIS-1.2.2",
                "Account lockout duration — data unavailable",
                "Lockout policy data could not be collected on this platform.",
                Category::AccountPolicy,
            )),
            Some(duration) if duration < 15 => findings.push(
                Finding::fail(
                    "CIS-1.2.2",
                    "Account lockout duration is below recommended minimum",
                    Severity::Low,
                    Category::AccountPolicy,
                    "A very short lockout duration allows attackers to quickly resume \
                     brute-force attempts after a lockout.",
                    format!("{} minutes", duration),
                    "15 or more minutes",
                    "Set 'Account lockout duration' to 15 minutes or more.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS WS2022 1.2.2",
                    "Ensure 'Account lockout duration' is set to '15 or more minute(s)'",
                )]),
            ),
            Some(_) => findings.push(Finding::pass(
                "CIS-1.2.2",
                "Account lockout duration meets recommended minimum",
                Category::AccountPolicy,
            )),
        }

        // CIS 1.2.3 — Reset account lockout counter after >= 15 minutes
        match policy.observation_window_minutes {
            None => findings.push(Finding::skip(
                "CIS-1.2.3",
                "Account lockout observation window — data unavailable",
                "Lockout policy data could not be collected on this platform.",
                Category::AccountPolicy,
            )),
            Some(window) if window < 15 => findings.push(
                Finding::fail(
                    "CIS-1.2.3",
                    "Account lockout observation window is below recommended minimum",
                    Severity::Low,
                    Category::AccountPolicy,
                    "A short observation window resets the failed-attempt counter quickly, \
                     allowing distributed slow-rate brute-force attacks to bypass the lockout.",
                    format!("{} minutes", window),
                    "15 or more minutes",
                    "Set 'Reset account lockout counter after' to 15 minutes or more.",
                )
                .with_refs(vec![ComplianceRef::cis(
                    "CIS WS2022 1.2.3",
                    "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'",
                )]),
            ),
            Some(_) => findings.push(Finding::pass(
                "CIS-1.2.3",
                "Account lockout observation window meets recommended minimum",
                Category::AccountPolicy,
            )),
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::Analyzer;
    use crate::models::finding::Severity;
    use crate::models::system_info::{LockoutPolicy, PasswordPolicy, SystemInfo};

    fn info_with_pw(policy: PasswordPolicy) -> SystemInfo {
        let mut info = SystemInfo::default();
        info.users.password_policy = policy;
        info
    }

    fn info_with_lockout(policy: LockoutPolicy) -> SystemInfo {
        let mut info = SystemInfo::default();
        info.users.lockout_policy = policy;
        info
    }

    #[test]
    fn password_policy_none_produces_skips() {
        let findings = PasswordPolicyAnalyzer.analyze(&SystemInfo::default()).unwrap();
        assert!(findings.iter().filter(|f| f.skipped).count() >= 4);
    }

    #[test]
    fn password_min_length_below_14_fails_high() {
        let info = info_with_pw(PasswordPolicy { min_length: Some(8), ..Default::default() });
        let findings = PasswordPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.1.1").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn password_min_length_14_passes() {
        let info = info_with_pw(PasswordPolicy { min_length: Some(14), ..Default::default() });
        let findings = PasswordPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.1.1").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn password_max_age_zero_fails_medium() {
        let info = info_with_pw(PasswordPolicy { max_age_days: Some(0), ..Default::default() });
        let findings = PasswordPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.1.2").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn password_max_age_over_365_fails_low() {
        let info = info_with_pw(PasswordPolicy { max_age_days: Some(366), ..Default::default() });
        let findings = PasswordPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.1.2").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn password_max_age_365_passes() {
        let info = info_with_pw(PasswordPolicy { max_age_days: Some(365), ..Default::default() });
        let findings = PasswordPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.1.2").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn password_history_below_24_fails_medium() {
        let info = info_with_pw(PasswordPolicy { history_count: Some(5), ..Default::default() });
        let findings = PasswordPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.1.3").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn password_history_24_passes() {
        let info = info_with_pw(PasswordPolicy { history_count: Some(24), ..Default::default() });
        let findings = PasswordPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.1.3").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn password_complexity_disabled_fails_high() {
        let info = info_with_pw(PasswordPolicy { complexity_required: Some(false), ..Default::default() });
        let findings = PasswordPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.1.4").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn password_complexity_enabled_passes() {
        let info = info_with_pw(PasswordPolicy { complexity_required: Some(true), ..Default::default() });
        let findings = PasswordPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.1.4").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn lockout_threshold_zero_fails_high() {
        let info = info_with_lockout(LockoutPolicy { threshold: Some(0), ..Default::default() });
        let findings = LockoutPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.2.1").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn lockout_threshold_over_5_fails_medium() {
        let info = info_with_lockout(LockoutPolicy { threshold: Some(10), ..Default::default() });
        let findings = LockoutPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.2.1").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn lockout_threshold_5_passes() {
        let info = info_with_lockout(LockoutPolicy { threshold: Some(5), ..Default::default() });
        let findings = LockoutPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.2.1").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn lockout_duration_below_15_fails_low() {
        let info = info_with_lockout(LockoutPolicy { duration_minutes: Some(5), ..Default::default() });
        let findings = LockoutPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.2.2").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn lockout_duration_15_passes() {
        let info = info_with_lockout(LockoutPolicy { duration_minutes: Some(15), ..Default::default() });
        let findings = LockoutPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.2.2").unwrap();
        assert!(f.passed);
    }

    #[test]
    fn lockout_window_below_15_fails_low() {
        let info = info_with_lockout(LockoutPolicy { observation_window_minutes: Some(10), ..Default::default() });
        let findings = LockoutPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.2.3").unwrap();
        assert!(!f.passed && !f.skipped);
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn lockout_window_15_passes() {
        let info = info_with_lockout(LockoutPolicy { observation_window_minutes: Some(15), ..Default::default() });
        let findings = LockoutPolicyAnalyzer.analyze(&info).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "CIS-1.2.3").unwrap();
        assert!(f.passed);
    }
}
