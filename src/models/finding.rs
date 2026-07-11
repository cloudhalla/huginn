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
