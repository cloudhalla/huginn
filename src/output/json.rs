use crate::error::HuginnError;
use crate::models::report::Report;

pub fn serialize(report: &Report) -> Result<String, HuginnError> {
    serde_json::to_string_pretty(report).map_err(HuginnError::Serialization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::system_info::SystemInfo;

    fn empty_report() -> Report {
        Report::new(SystemInfo::default(), vec![])
    }

    #[test]
    fn serialize_produces_valid_json() {
        let report = empty_report();
        let json = serialize(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn serialized_json_contains_required_fields() {
        let report = empty_report();
        let json = serialize(&report).unwrap();
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"findings\""));
        assert!(json.contains("\"summary\""));
    }
}
