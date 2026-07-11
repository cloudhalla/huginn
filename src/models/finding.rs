use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn weight(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    AccountPolicy,
    AuditPolicy,
    NetworkSecurity,
    ServiceSecurity,
    SoftwareSecurity,
    UserRights,
    FirewallPolicy,
    ScheduledTasks,
    SystemIntegrity,
    PatchManagement,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Category::AccountPolicy => "Account Policy",
            Category::AuditPolicy => "Audit Policy",
            Category::NetworkSecurity => "Network Security",
            Category::ServiceSecurity => "Service Security",
            Category::SoftwareSecurity => "Software Security",
            Category::UserRights => "User Rights",
            Category::FirewallPolicy => "Firewall Policy",
            Category::ScheduledTasks => "Scheduled Tasks",
            Category::SystemIntegrity => "System Integrity",
            Category::PatchManagement => "Patch Management",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRef {
    pub framework: String,
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl ComplianceRef {
    pub fn cis(id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            framework: "CIS".into(),
            id: id.into(),
            title: title.into(),
            url: Some("https://www.cisecurity.org/cis-benchmarks".into()),
        }
    }

    pub fn nist(id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            framework: "NIST".into(),
            id: id.into(),
            title: title.into(),
            url: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub severity_label: String,
    pub category: Category,
    pub category_label: String,
    pub description: String,
    pub current_value: String,
    pub expected_value: String,
    pub recommendation: String,
    pub references: Vec<ComplianceRef>,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    pub passed: bool,
    #[serde(default)]
    pub skipped: bool,
    #[serde(default)]
    pub os_target: String,
}

impl Finding {
    pub fn fail(
        rule_id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        category: Category,
        description: impl Into<String>,
        current_value: impl Into<String>,
        expected_value: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        let severity_label = severity.label().to_string();
        let category_label = category.label().to_string();
        Self {
            id: Uuid::new_v4(),
            rule_id: rule_id.into(),
            title: title.into(),
            severity,
            severity_label,
            category,
            category_label,
            description: description.into(),
            current_value: current_value.into(),
            expected_value: expected_value.into(),
            recommendation: recommendation.into(),
            references: Vec::new(),
            timestamp: Utc::now(),
            evidence: None,
            passed: false,
            skipped: false,
            os_target: String::new(),
        }
    }

    pub fn skip(
        rule_id: impl Into<String>,
        title: impl Into<String>,
        reason: impl Into<String>,
        category: Category,
    ) -> Self {
        let category_label = category.label().to_string();
        Self {
            id: Uuid::new_v4(),
            rule_id: rule_id.into(),
            title: title.into(),
            severity: Severity::Info,
            severity_label: "INFO".into(),
            category,
            category_label,
            description: reason.into(),
            current_value: String::new(),
            expected_value: String::new(),
            recommendation: String::new(),
            references: Vec::new(),
            timestamp: Utc::now(),
            evidence: None,
            passed: false,
            skipped: true,
            os_target: String::new(),
        }
    }

    pub fn pass(rule_id: impl Into<String>, title: impl Into<String>, category: Category) -> Self {
        let category_label = category.label().to_string();
        Self {
            id: Uuid::new_v4(),
            rule_id: rule_id.into(),
            title: title.into(),
            severity: Severity::Info,
            severity_label: "INFO".into(),
            category,
            category_label,
            description: String::new(),
            current_value: String::new(),
            expected_value: String::new(),
            recommendation: String::new(),
            references: Vec::new(),
            timestamp: Utc::now(),
            evidence: None,
            passed: true,
            skipped: false,
            os_target: String::new(),
        }
    }

    pub fn with_refs(mut self, refs: Vec<ComplianceRef>) -> Self {
        self.references = refs;
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_weights_are_ordered() {
        assert!(Severity::Critical.weight() > Severity::High.weight());
        assert!(Severity::High.weight() > Severity::Medium.weight());
        assert!(Severity::Medium.weight() > Severity::Low.weight());
        assert!(Severity::Low.weight() > Severity::Info.weight());
    }

    #[test]
    fn severity_labels_are_correct() {
        assert_eq!(Severity::Critical.label(), "CRITICAL");
        assert_eq!(Severity::High.label(), "HIGH");
        assert_eq!(Severity::Medium.label(), "MEDIUM");
        assert_eq!(Severity::Low.label(), "LOW");
        assert_eq!(Severity::Info.label(), "INFO");
    }

    #[test]
    fn fail_creates_failed_finding() {
        let f = Finding::fail(
            "TEST-1", "Title", Severity::High, Category::NetworkSecurity,
            "desc", "current", "expected", "rec",
        );
        assert!(!f.passed);
        assert!(!f.skipped);
        assert_eq!(f.rule_id, "TEST-1");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.severity_label, "HIGH");
        assert_eq!(f.current_value, "current");
        assert_eq!(f.expected_value, "expected");
        assert!(f.references.is_empty());
        assert!(f.evidence.is_none());
    }

    #[test]
    fn pass_creates_passed_finding() {
        let f = Finding::pass("TEST-2", "Title", Category::AccountPolicy);
        assert!(f.passed);
        assert!(!f.skipped);
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn skip_creates_skipped_finding() {
        let f = Finding::skip("TEST-3", "Title", "reason", Category::ServiceSecurity);
        assert!(!f.passed);
        assert!(f.skipped);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.description, "reason");
    }

    #[test]
    fn with_refs_attaches_compliance_refs() {
        let f = Finding::fail(
            "TEST-4", "Title", Severity::Low, Category::FirewallPolicy,
            "d", "c", "e", "r",
        )
        .with_refs(vec![ComplianceRef::cis("1.1", "Title")]);
        assert_eq!(f.references.len(), 1);
        assert_eq!(f.references[0].framework, "CIS");
    }

    #[test]
    fn with_evidence_attaches_evidence() {
        let f = Finding::fail(
            "TEST-5", "Title", Severity::Medium, Category::SystemIntegrity,
            "d", "c", "e", "r",
        )
        .with_evidence("evidence string");
        assert_eq!(f.evidence.as_deref(), Some("evidence string"));
    }

    #[test]
    fn compliance_ref_cis_sets_framework_and_url() {
        let r = ComplianceRef::cis("1.2.3", "Some control");
        assert_eq!(r.framework, "CIS");
        assert_eq!(r.id, "1.2.3");
        assert_eq!(r.title, "Some control");
        assert!(r.url.is_some());
    }

    #[test]
    fn compliance_ref_nist_has_no_url() {
        let r = ComplianceRef::nist("IA-5", "Authenticator Management");
        assert_eq!(r.framework, "NIST");
        assert!(r.url.is_none());
    }
}
