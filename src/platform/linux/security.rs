use std::collections::HashMap;

/// Parse /etc/ssh/sshd_config into a lowercase key → value map.
/// Only the first occurrence of each key is kept (matches sshd_config semantics).
pub fn read_ssh_config() -> HashMap<String, String> {
    let mut map = HashMap::new();

    let paths = ["/etc/ssh/sshd_config", "/etc/sshd_config"];
    let mut content = String::new();
    for path in &paths {
        if let Ok(c) = std::fs::read_to_string(path) {
            content = c;
            break;
        }
    }
    if content.is_empty() {
        return map;
    }

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // sshd_config lines are "Keyword Value" (space or tab separated, no '=')
        let mut parts = line.splitn(2, |c: char| c.is_ascii_whitespace());
        if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
            let key = key.to_lowercase();
            // Only keep first occurrence
            map.entry(key).or_insert_with(|| val.trim().to_string());
        }
    }
    map
}

/// Read a set of /proc/sys kernel parameters.
pub fn read_kernel_params() -> HashMap<String, String> {
    let params = [
        "kernel/randomize_va_space",
        "kernel/dmesg_restrict",
        "kernel/kptr_restrict",
        "kernel/core_uses_pid",
        "kernel/perf_event_paranoid",
        "fs/suid_dumpable",
        "net/ipv4/ip_forward",
        "net/ipv4/tcp_syncookies",
        "net/ipv4/conf/all/accept_redirects",
        "net/ipv4/conf/all/accept_source_route",
        "net/ipv4/conf/all/log_martians",
        "net/ipv4/conf/all/rp_filter",
        "net/ipv6/conf/all/accept_redirects",
        "net/ipv6/conf/all/disable_ipv6",
    ];

    let mut map = HashMap::new();
    for param in &params {
        let path = format!("/proc/sys/{}", param);
        if let Ok(val) = std::fs::read_to_string(&path) {
            map.insert(param.to_string(), val.trim().to_string());
        }
    }
    map
}
