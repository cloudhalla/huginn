use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BloodHoundOutput {
    pub meta: BloodHoundMeta,
    pub data: Vec<BloodHoundComputer>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BloodHoundMeta {
    #[serde(rename = "type")]
    pub kind: String,
    pub count: u32,
    pub version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BloodHoundComputer {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,

    #[serde(rename = "Properties")]
    pub properties: ComputerProperties,

    #[serde(rename = "HuginnAssessment")]
    pub huginn_assessment: HuginnAssessment,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComputerProperties {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub operatingsystem: String,
    pub operatingsystemversion: String,
    pub enabled: bool,
    pub haslaps: bool,
    pub unconstraineddelegation: bool,
    pub lastlogon: i64,
    pub lastlogontimestamp: i64,
    pub pwdlastset: i64,
    pub serviceprincipalnames: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HuginnAssessment {
    pub version: String,
    pub risk_score: u8,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub collected_at: String,
    pub top_findings: Vec<FindingRef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindingRef {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
}
