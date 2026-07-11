use crate::models::system_info::{FirewallProfile, NetworkInterface, OpenPort};
use super::super::linux::proc::{read_tcp_sockets, read_tcp6_sockets};

pub fn list_interfaces() -> Vec<NetworkInterface> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            let base = format!("/sys/class/net/{}", name);

            let is_up = std::fs::read_to_string(format!("{}/operstate", base))
                .map(|s| s.trim() == "up")
                .unwrap_or(false);

            let mac_address = std::fs::read_to_string(format!("{}/address", base))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s != "00:00:00:00:00:00");

            // Get IP addresses via /proc/net/if_inet6 and /proc/net/fib_trie
            // Simplified: just read from ip command if available
            let ip_addresses = get_ip_addresses(&name);

            Some(NetworkInterface {
                name,
                mac_address,
                ip_addresses,
                dns_servers: Vec::new(), // populated from /etc/resolv.conf separately
                dhcp_enabled: false,     // complex to detect without dhclient state
                is_up,
            })
        })
        .collect()
}

fn get_ip_addresses(iface: &str) -> Vec<String> {
    // Try reading from /proc/net/if_inet6 for IPv6
    // For IPv4, try ip command
    let mut addrs = Vec::new();

    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show", iface])
        .output()
    {
        let out = String::from_utf8_lossy(&output.stdout);
        for line in out.lines() {
            let line = line.trim();
            if line.starts_with("inet ") || line.starts_with("inet6 ") {
                if let Some(addr) = line.split_whitespace().nth(1) {
                    // addr includes prefix length, e.g. "192.168.1.1/24"
                    addrs.push(addr.to_string());
                }
            }
        }
    }

    addrs
}

pub fn list_open_ports() -> Vec<OpenPort> {
    let proc_names = super::proc::read_process_names();
    let mut ports = Vec::new();

    for (addr, port, state, _uid) in read_tcp_sockets() {
        if state != "LISTEN" {
            continue;
        }
        ports.push(OpenPort {
            protocol: "TCP".to_string(),
            local_addr: addr,
            local_port: port,
            state,
            process_name: find_process_for_port(port, &proc_names),
            ..Default::default()
        });
    }

    for (addr, port, state, _uid) in read_tcp6_sockets() {
        if state != "LISTEN" {
            continue;
        }
        ports.push(OpenPort {
            protocol: "TCP6".to_string(),
            local_addr: addr,
            local_port: port,
            state,
            process_name: find_process_for_port(port, &proc_names),
            ..Default::default()
        });
    }

    ports
}

fn find_process_for_port(
    _port: u16,
    _proc_names: &std::collections::HashMap<u32, String>,
) -> Option<String> {
    // Would need to correlate /proc/*/net/tcp entries with /proc/*/fd symlinks
    // Complex - skip for now
    None
}

pub fn get_firewall_status() -> Vec<FirewallProfile> {
    let mut profiles = Vec::new();

    // Check ufw status
    if let Ok(output) = std::process::Command::new("ufw")
        .arg("status")
        .output()
    {
        let out = String::from_utf8_lossy(&output.stdout);
        let enabled = out.contains("Status: active");
        profiles.push(FirewallProfile {
            name: "ufw".to_string(),
            enabled,
            inbound_default: if enabled {
                "Block".to_string()
            } else {
                "Allow".to_string()
            },
            outbound_default: "Allow".to_string(),
        });
        return profiles;
    }

    // Check iptables
    if let Ok(output) = std::process::Command::new("iptables")
        .args(["-L", "-n", "--line-numbers"])
        .output()
    {
        let out = String::from_utf8_lossy(&output.stdout);
        let has_rules = out.lines().count() > 10;
        profiles.push(FirewallProfile {
            name: "iptables".to_string(),
            enabled: has_rules,
            inbound_default: "Unknown".to_string(),
            outbound_default: "Unknown".to_string(),
        });
    }

    profiles
}

pub fn check_smb_v1() -> Option<bool> {
    // Check if samba is installed and smb1 is enabled
    if let Ok(content) = std::fs::read_to_string("/etc/samba/smb.conf") {
        for line in content.lines() {
            let line = line.trim().to_lowercase();
            if line.starts_with("min protocol") {
                // If min protocol is below SMB2, SMBv1 is potentially enabled
                if line.contains("nt1") || line.contains("smb1") {
                    return Some(true);
                }
                return Some(false);
            }
        }
    }
    None
}
