use crate::models::system_info::{ServiceInfo, ServiceStartType, ServiceState};
use std::collections::HashMap;

pub fn list_services() -> Vec<ServiceInfo> {
    let Ok(units_out) = std::process::Command::new("systemctl")
        .args(["list-units", "--type=service", "--all", "--no-pager", "--plain"])
        .output()
    else {
        return Vec::new();
    };

    if !units_out.status.success() {
        return Vec::new();
    }

    let start_types = collect_unit_file_states();
    let binary_paths = collect_binary_paths();

    parse_systemctl_output(
        &String::from_utf8_lossy(&units_out.stdout),
        &start_types,
        &binary_paths,
    )
}

fn collect_unit_file_states() -> HashMap<String, ServiceStartType> {
    let mut map = HashMap::new();
    let Ok(out) = std::process::Command::new("systemctl")
        .args(["list-unit-files", "--type=service", "--no-pager", "--plain"])
        .output()
    else {
        return map;
    };

    for line in String::from_utf8_lossy(&out.stdout).lines().skip(1) {
        let mut parts = line.split_whitespace();
        let Some(unit) = parts.next() else { continue };
        let Some(state) = parts.next() else { continue };
        let name = unit.trim_end_matches(".service");
        let start_type = match state {
            "enabled" | "enabled-runtime" => ServiceStartType::Automatic,
            "disabled" => ServiceStartType::Disabled,
            "static" | "indirect" | "alias" => ServiceStartType::Manual,
            _ => ServiceStartType::Unknown,
        };
        map.insert(name.to_string(), start_type);
    }
    map
}

fn collect_binary_paths() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let dirs = [
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/etc/systemd/system",
        "/run/systemd/system",
    ];
    for dir in &dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            if !fname_str.ends_with(".service") {
                continue;
            }
            let name = fname_str.trim_end_matches(".service").to_string();
            if map.contains_key(&name) {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(entry.path()) else { continue };
            for line in content.lines() {
                if let Some(exec) = line.strip_prefix("ExecStart=") {
                    // Strip leading flag characters (@, -, :, !, +)
                    let exec = exec.trim_start_matches(|c: char| "@-:!+".contains(c));
                    if let Some(binary) = exec.split_whitespace().next() {
                        if !binary.is_empty() && binary != "-" {
                            map.insert(name, binary.to_string());
                        }
                    }
                    break;
                }
            }
        }
    }
    map
}

fn parse_systemctl_output(
    output: &str,
    start_types: &HashMap<String, ServiceStartType>,
    binary_paths: &HashMap<String, String>,
) -> Vec<ServiceInfo> {
    output
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                return None;
            }

            let unit_name = parts[0];
            if !unit_name.ends_with(".service") {
                return None;
            }

            let name = unit_name.trim_end_matches(".service").to_string();
            let load  = parts[1];
            let sub   = parts[3];

            if load == "not-found" {
                return None;
            }

            let state = match sub {
                "running" => ServiceState::Running,
                "exited" | "dead" | "failed" => ServiceState::Stopped,
                _ => ServiceState::Unknown,
            };

            let start_type = start_types
                .get(&name)
                .cloned()
                .unwrap_or(ServiceStartType::Unknown);

            let binary_path = binary_paths.get(&name).cloned();

            Some(ServiceInfo {
                display_name: name.clone(),
                name,
                state,
                start_type,
                binary_path,
                ..Default::default()
            })
        })
        .collect()
}
