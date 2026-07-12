use std::process::Command;

use crate::error::HuginnError;
use crate::models::system_info::{ScheduledTask, ScheduledTasksInfo};

/// Column indices in `schtasks /query /fo csv /v /nh` output.
/// Values documented on Microsoft Learn; ordering is stable across locales
/// even though header labels are localized.
const COL_TASK_NAME: usize = 1;
const COL_NEXT_RUN: usize = 2;
const COL_STATUS: usize = 3;
const COL_LAST_RUN: usize = 5;
const COL_AUTHOR: usize = 7;
const COL_TASK_TO_RUN: usize = 8;
const COL_TASK_STATE: usize = 11;
const COL_RUN_AS_USER: usize = 14;
const COL_SCHEDULE_TYPE: usize = 18;

pub fn collect(info: &mut ScheduledTasksInfo) -> Result<(), HuginnError> {
    info.tasks = query_scheduled_tasks();
    Ok(())
}

fn query_scheduled_tasks() -> Vec<ScheduledTask> {
    let Ok(output) = Command::new("schtasks")
        .args(["/query", "/fo", "csv", "/v", "/nh"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_csv_rows(&text)
        .into_iter()
        .filter_map(|row| build_task(&row))
        .collect()
}

fn build_task(row: &[String]) -> Option<ScheduledTask> {
    let raw_name = row.get(COL_TASK_NAME)?.trim().to_string();
    if raw_name.is_empty() || raw_name.eq_ignore_ascii_case("TaskName") {
        return None;
    }
    // Skip synthetic "folder-only" rows that some Windows builds emit — they
    // report the parent folder path with N/A everywhere else.
    let status = row.get(COL_STATUS).map(|s| s.as_str()).unwrap_or("").trim();
    if status.is_empty() && row.get(COL_TASK_TO_RUN).map(|s| s.trim().is_empty()).unwrap_or(true) {
        return None;
    }

    let (path, name) = split_task_path(&raw_name);
    let action = optional_field(row, COL_TASK_TO_RUN);
    let run_as = optional_field(row, COL_RUN_AS_USER);
    let author = optional_field(row, COL_AUTHOR);
    let trigger = optional_field(row, COL_SCHEDULE_TYPE);
    let _next_run = row.get(COL_NEXT_RUN); // Locale-formatted; not surfaced.
    let _last_run = row.get(COL_LAST_RUN); // Locale-formatted; not surfaced.
    let enabled = row
        .get(COL_TASK_STATE)
        .map(|s| !s.trim().eq_ignore_ascii_case("Disabled"))
        .unwrap_or(true);

    let _ = author; // Reserved for future analyzers.

    Some(ScheduledTask {
        name,
        path: Some(path),
        action,
        run_as,
        trigger,
        enabled,
        last_run: None,
        next_run: None,
        // Hidden lives in the XML definition under Settings; not exposed by schtasks CSV.
        hidden: false,
    })
}

fn optional_field(row: &[String], idx: usize) -> Option<String> {
    let v = row.get(idx)?.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("N/A") {
        None
    } else {
        Some(v.to_string())
    }
}

fn split_task_path(full: &str) -> (String, String) {
    // Tasks are named like `\Microsoft\Windows\Foo\Bar` — split at the last backslash.
    if let Some(idx) = full.rfind('\\') {
        let path = &full[..idx];
        let name = &full[idx + 1..];
        let path = if path.is_empty() { "\\" } else { path };
        (path.to_string(), name.to_string())
    } else {
        ("\\".to_string(), full.to_string())
    }
}

// ---------------------------------------------------------------------------
// CSV parsing — handles quoted fields with embedded commas and `""` escapes.
// ---------------------------------------------------------------------------

fn parse_csv_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    fields.push(std::mem::take(&mut field));
                }
                '\r' => { /* consumed by \n branch */ }
                '\n' => {
                    fields.push(std::mem::take(&mut field));
                    if !fields.iter().all(|f| f.is_empty()) {
                        rows.push(std::mem::take(&mut fields));
                    } else {
                        fields.clear();
                    }
                }
                _ => field.push(c),
            }
        }
    }
    if !field.is_empty() || !fields.is_empty() {
        fields.push(field);
        if !fields.iter().all(|f| f.is_empty()) {
            rows.push(fields);
        }
    }
    rows
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_csv_row() {
        let rows = parse_csv_rows("a,b,c\n");
        assert_eq!(rows, vec![vec!["a", "b", "c"]]);
    }

    #[test]
    fn parses_quoted_field_with_comma() {
        let rows = parse_csv_rows("a,\"b,c\",d\n");
        assert_eq!(rows, vec![vec!["a", "b,c", "d"]]);
    }

    #[test]
    fn parses_escaped_quote() {
        let rows = parse_csv_rows("a,\"say \"\"hi\"\"\",b\n");
        assert_eq!(rows, vec![vec!["a", "say \"hi\"", "b"]]);
    }

    #[test]
    fn skips_blank_lines() {
        let rows = parse_csv_rows("a,b\n\nc,d\n");
        assert_eq!(rows, vec![vec!["a", "b"], vec!["c", "d"]]);
    }

    #[test]
    fn split_task_path_nested() {
        assert_eq!(
            split_task_path(r"\Microsoft\Windows\Foo\Bar"),
            (r"\Microsoft\Windows\Foo".to_string(), "Bar".to_string())
        );
    }

    #[test]
    fn split_task_path_root() {
        assert_eq!(
            split_task_path(r"\Foo"),
            (r"\".to_string(), "Foo".to_string())
        );
    }

    #[test]
    fn optional_field_treats_na_as_none() {
        let row = vec!["".to_string(), "N/A".to_string(), "value".to_string()];
        assert!(optional_field(&row, 0).is_none());
        assert!(optional_field(&row, 1).is_none());
        assert_eq!(optional_field(&row, 2), Some("value".to_string()));
    }

    #[test]
    fn build_task_uses_disabled_state() {
        let mut row = vec![String::new(); 20];
        row[COL_TASK_NAME] = r"\Vendor\Test".to_string();
        row[COL_STATUS] = "Ready".to_string();
        row[COL_TASK_STATE] = "Disabled".to_string();
        row[COL_TASK_TO_RUN] = r"C:\Vendor\svc.exe".to_string();
        let task = build_task(&row).unwrap();
        assert!(!task.enabled);
        assert_eq!(task.name, "Test");
        assert_eq!(task.path.as_deref(), Some(r"\Vendor"));
        assert_eq!(task.action.as_deref(), Some(r"C:\Vendor\svc.exe"));
    }

    #[test]
    fn build_task_skips_header_row() {
        let mut row = vec![String::new(); 20];
        row[COL_TASK_NAME] = "TaskName".to_string();
        assert!(build_task(&row).is_none());
    }
}
