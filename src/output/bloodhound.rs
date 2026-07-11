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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::report::Report;
    use crate::models::system_info::SystemInfo;

    fn empty_report() -> Report {
        Report::new(SystemInfo::default(), vec![])
    }

    #[test]
    fn bloodhound_output_meta_is_correct() {
        let report = empty_report();
        let output = build_bloodhound_output(&report);
        assert_eq!(output.meta.kind, "computers");
        assert_eq!(output.meta.count, 1);
        assert_eq!(output.meta.version, 4);
    }

    #[test]
    fn bloodhound_output_has_one_computer() {
        let report = empty_report();
        let output = build_bloodhound_output(&report);
        assert_eq!(output.data.len(), 1);
    }

    #[test]
    fn bloodhound_risk_score_matches_report() {
        let report = empty_report();
        let expected_score = report.summary.risk_score;
        let output = build_bloodhound_output(&report);
        assert_eq!(output.data[0].huginn_assessment.risk_score, expected_score);
    }

    #[test]
    fn bloodhound_total_findings_matches_report() {
        let report = empty_report();
        let output = build_bloodhound_output(&report);
        assert_eq!(
            output.data[0].huginn_assessment.total_findings,
            report.summary.total_failed()
        );
    }
}
