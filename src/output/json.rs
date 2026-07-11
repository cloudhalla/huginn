use crate::error::HuginnError;
use crate::models::report::Report;

pub fn serialize(report: &Report) -> Result<String, HuginnError> {
    serde_json::to_string_pretty(report).map_err(HuginnError::Serialization)
}
