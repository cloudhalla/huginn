pub fn read_uptime() -> Option<u64> {
    std::fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|s| s as u64)
}

/// Returns a map of PID → process name from /proc.
pub fn read_process_names() -> std::collections::HashMap<u32, String> {
    let mut map = std::collections::HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let comm_path = format!("/proc/{}/comm", pid);
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            map.insert(pid, comm.trim().to_string());
        }
    }
    map
}

/// Parse /proc/net/tcp for listening TCP sockets.
/// Returns (local_addr, local_port, state, uid) tuples.
pub fn read_tcp_sockets() -> Vec<(String, u16, String, u32)> {
    parse_net_tcp("/proc/net/tcp")
}

pub fn read_tcp6_sockets() -> Vec<(String, u16, String, u32)> {
    parse_net_tcp("/proc/net/tcp6")
}

fn parse_net_tcp(path: &str) -> Vec<(String, u16, String, u32)> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    let state_map = |s: &str| match s {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    };

    content
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 {
                return None;
            }
            let local = parts[1];
            let state_hex = parts[3];
            let uid: u32 = parts[7].parse().ok()?;

            let (addr_hex, port_hex) = local.split_once(':')?;
            let port = u16::from_str_radix(port_hex, 16).ok()?;

            // Decode address (little-endian 32-bit or 128-bit)
            let addr = decode_hex_addr(addr_hex);
            let state = state_map(state_hex).to_string();

            Some((addr, port, state, uid))
        })
        .collect()
}

fn decode_hex_addr(hex: &str) -> String {
    if hex.len() == 8 {
        // IPv4 little-endian
        let n = u32::from_str_radix(hex, 16).unwrap_or(0);
        let b = n.to_le_bytes();
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    } else {
        // IPv6 — simplified, just return hex for now
        hex.to_string()
    }
}
