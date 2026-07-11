use crate::models::system_info::{DnsInfo, DnsLinkInfo, FirewallProfile, NetworkInterface, OpenPort};
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

pub fn collect_dns_info() -> Option<DnsInfo> {
    let output = std::process::Command::new("resolvectl")
        .arg("status")
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    if text.trim().is_empty() {
        return None;
    }

    let mut info = DnsInfo::default();
    let mut current_link: Option<DnsLinkInfo> = None;
    let mut in_global = false;

    for line in text.lines() {
        // Detect section headers
        if line.trim_start() == "Global" {
            if let Some(link) = current_link.take() {
                info.links.push(link);
            }
            in_global = true;
            continue;
        }

        // "Link 2 (eth0)" or "Link 10 (eth1)"
        if line.starts_with("Link ") && line.contains('(') {
            if let Some(link) = current_link.take() {
                info.links.push(link);
            }
            in_global = false;

            let rest = &line["Link ".len()..];
            let paren = rest.find('(').unwrap_or(rest.len());
            let index: u32 = rest[..paren].trim().parse().unwrap_or(0);
            let name = if paren + 1 < rest.len() {
                rest[paren + 1..].trim_end_matches(')').trim().to_string()
            } else {
                String::new()
            };
            current_link = Some(DnsLinkInfo {
                index,
                name,
                ..Default::default()
            });
            continue;
        }

        // Parse key: value pairs (indented lines)
        let trimmed = line.trim_start();
        if let Some((raw_key, val)) = trimmed.split_once(':') {
            let key = raw_key.trim().to_lowercase();
            let val = val.trim().to_string();

            if in_global {
                match key.as_str() {
                    "protocols" => info.protocols = Some(val),
                    "resolv.conf mode" => info.resolv_conf_mode = Some(val),
                    "current dns server" => info.current_dns_server = Some(val),
                    "dns servers" => {
                        if !val.is_empty() {
                            info.dns_servers.push(val);
                        }
                    }
                    "dns domain" => info.dns_domain = Some(val),
                    _ => {}
                }
            } else if let Some(ref mut link) = current_link {
                match key.as_str() {
                    "current scopes" => link.current_scopes = Some(val),
                    "protocols" => link.protocols = Some(val),
                    "current dns server" => link.current_dns_server = Some(val),
                    "dns servers" => {
                        if !val.is_empty() {
                            link.dns_servers.push(val);
                        }
                    }
                    "dns domain" => link.dns_domain = Some(val),
                    _ => {}
                }
            }
        } else if trimmed.starts_with(' ') || line.starts_with("        ") {
            // Continuation line for multi-value fields (e.g. additional DNS servers)
            let val = trimmed.trim().to_string();
            if !val.is_empty() {
                if in_global {
                    info.dns_servers.push(val);
                } else if let Some(ref mut link) = current_link {
                    link.dns_servers.push(val);
                }
            }
        }
    }

    if let Some(link) = current_link {
        info.links.push(link);
    }

    Some(info)
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
