use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::finding::{Finding, Severity};
use super::system_info::SystemInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeveritySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub passed: usize,
    pub skipped: usize,
    pub risk_score: u8,
}

impl SeveritySummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            passed: 0,
            skipped: 0,
            risk_score: 0,
        };
        for f in findings {
            if f.skipped {
                s.skipped += 1;
                continue;
            }
            if f.passed {
                s.passed += 1;
                continue;
            }
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
                Severity::Info => s.info += 1,
            }
        }
        s.risk_score = s.compute_risk_score();
        s
    }

    fn compute_risk_score(&self) -> u8 {
        let raw = self.critical * 5
            + self.high * 4
            + self.medium * 3
            + self.low * 2
            + self.info;
        // skipped rules don't count toward the denominator — score based on rules with data
        let total = self.critical + self.high + self.medium + self.low + self.info + self.passed;
        if total == 0 {
            return 0;
        }
        ((raw * 100) / (total * 5)).min(100) as u8
    }

    pub fn total_failed(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub generated_at_display: String,
    pub target_hostname: String,
    pub target_os: String,
    pub system_info: SystemInfo,
    pub findings: Vec<Finding>,
    pub summary: SeveritySummary,
}

impl Report {
    pub fn new(system_info: SystemInfo, mut findings: Vec<Finding>) -> Self {
        findings.sort_by(|a, b| {
            b.severity
                .weight()
                .cmp(&a.severity.weight())
                .then(a.rule_id.cmp(&b.rule_id))
        });

        let summary = SeveritySummary::from_findings(&findings);
        let generated_at = Utc::now();

        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            generated_at,
            generated_at_display: generated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            target_hostname: system_info.os.hostname.clone(),
            target_os: system_info.os.name.clone(),
            system_info,
            findings,
            summary,
        }
    }

    pub fn failed_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| !f.passed && !f.skipped)
    }
}
