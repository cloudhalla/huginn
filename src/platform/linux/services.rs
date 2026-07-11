use crate::models::system_info::{ServiceInfo, ServiceStartType, ServiceState};

pub fn list_services() -> Vec<ServiceInfo> {
    // Try systemctl for systemd systems
    if let Ok(output) = std::process::Command::new("systemctl")
        .args(["list-units", "--type=service", "--all", "--no-pager", "--plain"])
        .output()
    {
        if output.status.success() {
            return parse_systemctl_output(&String::from_utf8_lossy(&output.stdout));
        }
    }

    Vec::new()
}

fn parse_systemctl_output(output: &str) -> Vec<ServiceInfo> {
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
            let load = parts[1];
            let active = parts[2];
            let sub = parts[3];

            if load == "not-found" {
                return None;
            }

            let state = match sub {
                "running" => ServiceState::Running,
                "exited" | "dead" | "failed" => ServiceState::Stopped,
                _ => ServiceState::Unknown,
            };

            let _ = active; // suppress unused warning

            Some(ServiceInfo {
                name: name.clone(),
                display_name: name,
                state,
                start_type: ServiceStartType::Unknown,
                ..Default::default()
            })
        })
        .collect()
}
