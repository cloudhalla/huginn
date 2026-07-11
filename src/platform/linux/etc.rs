use std::collections::HashMap;
use crate::models::system_info::{
    InstalledSoftware, LocalUser, LockoutPolicy, PasswordPolicy, ScheduledTask,
};

pub fn read_os_release() -> HashMap<String, String> {
    let content = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();

    content
        .lines()
        .filter_map(|line| {
            let (key, val) = line.split_once('=')?;
            let val = val.trim_matches('"').to_string();
            Some((key.to_string(), val))
        })
        .collect()
}

pub fn read_domain() -> Option<String> {
    // Check /etc/sssd/sssd.conf or /etc/krb5.conf for domain membership
    if let Ok(content) = std::fs::read_to_string("/etc/krb5.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("default_realm") {
                return line.split('=').nth(1).map(|s| s.trim().to_string());
            }
        }
    }

    // Check resolv.conf for search domain
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("domain ") {
                return Some(line[7..].trim().to_string());
            }
        }
    }

    None
}

pub fn read_passwd_users() -> Vec<LocalUser> {
    let content = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let shadow = read_shadow_map();
    let sudo_members = read_sudo_group();

    content
        .lines()
        .filter_map(|line| parse_passwd_line(line, &shadow, &sudo_members))
        .collect()
}

fn parse_passwd_line(
    line: &str,
    shadow: &HashMap<String, ShadowEntry>,
    sudo_members: &[String],
) -> Option<LocalUser> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return None;
    }

    let username = parts[0].to_string();
    let uid: u32 = parts[2].parse().ok()?;
    let shell = parts[6];

    let enabled = !shell.ends_with("nologin")
        && !shell.ends_with("/false")
        && !shell.ends_with("/sync");

    let is_admin = sudo_members.contains(&username) || uid == 0;

    let shadow_entry = shadow.get(&username);
    let password_required = shadow_entry
        .map(|e| e.password_hash != "*" && e.password_hash != "!" && !e.password_hash.is_empty())
        .unwrap_or(true);

    let password_expires = shadow_entry
        .and_then(|e| e.max_days)
        .map(|d| d > 0)
        .unwrap_or(false);

    Some(LocalUser {
        username,
        uid: Some(uid),
        enabled,
        is_admin,
        password_required,
        password_expires,
        ..Default::default()
    })
}

struct ShadowEntry {
    password_hash: String,
    max_days: Option<i64>,
}

fn read_shadow_map() -> HashMap<String, ShadowEntry> {
    let content = std::fs::read_to_string("/etc/shadow").unwrap_or_default();
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 5 {
                return None;
            }
            let username = parts[0].to_string();
            let password_hash = parts[1].to_string();
            let max_days: Option<i64> = parts[4].parse().ok();
            Some((
                username,
                ShadowEntry {
                    password_hash,
                    max_days,
                },
            ))
        })
        .collect()
}

pub fn read_sudo_group() -> Vec<String> {
    let content = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let mut members = Vec::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let group = parts[0];
        if group == "sudo" || group == "wheel" || group == "admin" {
            for member in parts[3].split(',') {
                let m = member.trim();
                if !m.is_empty() {
                    members.push(m.to_string());
                }
            }
        }
    }

    members
}

pub fn read_pam_password_policy() -> PasswordPolicy {
    let mut policy = PasswordPolicy::default();

    // Try /etc/security/pwquality.conf
    if let Ok(content) = std::fs::read_to_string("/etc/security/pwquality.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                let key = key.trim();
                let val = val.trim();
                match key {
                    "minlen" => policy.min_length = val.parse().ok(),
                    "dcredit" | "ucredit" | "ocredit" | "lcredit" => {
                        // If any credit is < 0, complexity is required
                        if val.parse::<i32>().unwrap_or(0) < 0 {
                            policy.complexity_required = Some(true);
                        }
                    }
                    "remember" => policy.history_count = val.parse().ok(),
                    _ => {}
                }
            }
        }
    }

    // Try /etc/login.defs for password aging
    if let Ok(content) = std::fs::read_to_string("/etc/login.defs") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            match parts[0] {
                "PASS_MAX_DAYS" => policy.max_age_days = parts[1].parse().ok(),
                "PASS_MIN_DAYS" => policy.min_age_days = parts[1].parse().ok(),
                "PASS_MIN_LEN" => {
                    if policy.min_length.is_none() {
                        policy.min_length = parts[1].parse().ok();
                    }
                }
                _ => {}
            }
        }
    }

    policy
}

pub fn read_pam_lockout_policy() -> LockoutPolicy {
    let mut policy = LockoutPolicy::default();

    // Try /etc/security/faillock.conf (modern pam_faillock)
    if let Ok(content) = std::fs::read_to_string("/etc/security/faillock.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                let key = key.trim();
                let val = val.trim();
                match key {
                    "deny" => policy.threshold = val.parse().ok(),
                    "unlock_time" => {
                        // unlock_time is in seconds, convert to minutes
                        policy.duration_minutes =
                            val.parse::<u32>().ok().map(|s| s / 60);
                    }
                    "fail_interval" => {
                        policy.observation_window_minutes =
                            val.parse::<u32>().ok().map(|s| s / 60);
                    }
                    _ => {}
                }
            }
        }
    }

    policy
}

pub fn read_dns_servers() -> Vec<String> {
    let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("nameserver ") {
                Some(line[11..].trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

pub fn list_installed_packages() -> Vec<InstalledSoftware> {
    // Try dpkg (Debian/Ubuntu)
    if let Ok(output) = std::process::Command::new("dpkg-query")
        .args(["--show", "--showformat=${Package}\t${Version}\t${Maintainer}\n"])
        .output()
    {
        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(3, '\t').collect();
                    if parts.len() < 2 {
                        return None;
                    }
                    let name = parts[0].to_string();
                    let version = Some(parts[1].to_string());
                    let vendor = parts.get(2).map(|s| s.to_string());
                    let is_av = is_av_package(&name);
                    Some(InstalledSoftware {
                        name,
                        version,
                        vendor,
                        is_av_or_edr: is_av,
                        ..Default::default()
                    })
                })
                .collect();
        }
    }

    Vec::new()
}

fn is_av_package(name: &str) -> bool {
    let av_keywords = [
        "clamav", "sophos", "eset", "avast", "kaspersky", "trend", "crowdstrike",
        "sentinel", "cylance", "carbon", "defender", "rkhunter", "chkrootkit",
    ];
    let name_lower = name.to_lowercase();
    av_keywords.iter().any(|kw| name_lower.contains(kw))
}

pub fn list_cron_jobs() -> Vec<ScheduledTask> {
    let mut tasks = Vec::new();

    // System crontabs
    let cron_dirs = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ];

    for dir in &cron_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            tasks.push(ScheduledTask {
                name,
                path: Some(path.to_string_lossy().to_string()),
                enabled: true,
                run_as: Some("root".to_string()),
                ..Default::default()
            });
        }
    }

    // /etc/crontab
    if std::fs::metadata("/etc/crontab").is_ok() {
        tasks.push(ScheduledTask {
            name: "crontab".to_string(),
            path: Some("/etc/crontab".to_string()),
            enabled: true,
            ..Default::default()
        });
    }

    tasks
}
