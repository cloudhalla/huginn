use crate::models::bloodhound::{
    BloodHoundComputer, BloodHoundMeta, BloodHoundOutput, ComputerProperties, FindingRef,
    HuginnAssessment,
};
use crate::models::report::Report;

pub fn build_bloodhound_output(report: &Report) -> BloodHoundOutput {
    let si = &report.system_info;
    let hostname_upper = report.target_hostname.to_uppercase();
    let fqdn = match &si.os.domain {
        Some(d) => format!("{}.{}", hostname_upper, d.to_uppercase()),
        None => hostname_upper.clone(),
    };

    let top_findings: Vec<FindingRef> = report
        .failed_findings()
        .take(10)
        .map(|f| FindingRef {
            rule_id: f.rule_id.clone(),
            title: f.title.clone(),
            severity: f.severity_label.clone(),
            category: f.category_label.clone(),
        })
        .collect();

    let computer = BloodHoundComputer {
        object_identifier: si
            .users
            .users
            .first()
            .and_then(|u| u.sid.clone())
            .unwrap_or_else(|| format!("HUGINN-{}", hostname_upper)),
        properties: ComputerProperties {
            name: fqdn,
            domain: si.os.domain.clone(),
            operatingsystem: si.os.name.clone(),
            operatingsystemversion: si.os.version.clone(),
            enabled: true,
            haslaps: false,
            unconstraineddelegation: false,
            lastlogon: report.generated_at.timestamp(),
            lastlogontimestamp: report.generated_at.timestamp(),
            pwdlastset: 0,
            serviceprincipalnames: Vec::new(),
            description: Some(format!(
                "Huginn assessment v{} | Risk Score: {}",
                report.version, report.summary.risk_score
            )),
        },
        huginn_assessment: HuginnAssessment {
            version: report.version.clone(),
            risk_score: report.summary.risk_score,
            total_findings: report.summary.total_failed(),
            critical: report.summary.critical,
            high: report.summary.high,
            medium: report.summary.medium,
            low: report.summary.low,
            collected_at: report.generated_at_display.clone(),
            top_findings,
        },
    };

    BloodHoundOutput {
        meta: BloodHoundMeta {
            kind: "computers".into(),
            count: 1,
            version: 4,
        },
        data: vec![computer],
    }
}
