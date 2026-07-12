use std::net::{Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetExtendedTcpTable,
    GetExtendedUdpTable, IP_ADAPTER_ADDRESSES_LH, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

use crate::models::system_info::{FirewallProfile, NetworkInterface, OpenPort};

use super::registry;

// IP_ADAPTER_ADDRESSES flag bits (from iptypes.h)
const IP_ADAPTER_DHCP_ENABLED: u32 = 0x0004;

const TCP_STATE_LISTEN: u32 = 2;

pub fn list_interfaces() -> Vec<NetworkInterface> {
    let mut buf = vec![0u8; 32 * 1024];
    let mut size = buf.len() as u32;

    // Retry once if the buffer wasn't large enough.
    for _ in 0..2 {
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };

        if rc == NO_ERROR.0 {
            return parse_adapters(buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH);
        }
        if rc == ERROR_BUFFER_OVERFLOW.0 || rc == ERROR_INSUFFICIENT_BUFFER.0 {
            buf.resize(size as usize, 0);
            continue;
        }
        break;
    }
    Vec::new()
}

fn parse_adapters(head: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<NetworkInterface> {
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        let adapter = unsafe { &*cursor };
        let name = pwstr_to_string_lossy(adapter.FriendlyName.0);

        let mac_len = adapter.PhysicalAddressLength as usize;
        let mac_address = if mac_len == 0 {
            None
        } else {
            let bytes = &adapter.PhysicalAddress[..mac_len.min(adapter.PhysicalAddress.len())];
            Some(bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":"))
        };

        let mut ip_addresses = Vec::new();
        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            let u = unsafe { &*unicast };
            if !u.Address.lpSockaddr.is_null() {
                if let Some(addr) =
                    sockaddr_to_string(u.Address.lpSockaddr, Some(u.OnLinkPrefixLength))
                {
                    ip_addresses.push(addr);
                }
            }
            unicast = u.Next;
        }

        let mut dns_servers = Vec::new();
        let mut dns = adapter.FirstDnsServerAddress;
        while !dns.is_null() {
            let d = unsafe { &*dns };
            if !d.Address.lpSockaddr.is_null() {
                if let Some(addr) = sockaddr_to_string(d.Address.lpSockaddr, None) {
                    dns_servers.push(addr);
                }
            }
            dns = d.Next;
        }

        let flags = unsafe { adapter.Anonymous2.Anonymous._bitfield };
        let dhcp_enabled = flags & IP_ADAPTER_DHCP_ENABLED != 0;
        let is_up = adapter.OperStatus == IfOperStatusUp;

        out.push(NetworkInterface {
            name,
            mac_address,
            ip_addresses,
            dns_servers,
            dhcp_enabled,
            is_up,
        });

        cursor = adapter.Next;
    }
    out
}

fn sockaddr_to_string(sa: *const SOCKADDR, prefix: Option<u8>) -> Option<String> {
    if sa.is_null() {
        return None;
    }
    let family = unsafe { (*sa).sa_family };
    if family == AF_INET {
        let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
        let raw = unsafe { sin.sin_addr.S_un.S_addr };
        // S_addr is stored in network byte order; Ipv4Addr::from(u32) treats it as host-order,
        // so build it from the same 4 bytes in order.
        let octets = raw.to_ne_bytes();
        let addr = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        Some(match prefix {
            Some(p) => format!("{}/{}", addr, p),
            None => addr.to_string(),
        })
    } else if family == AF_INET6 {
        let sin6 = unsafe { &*(sa as *const SOCKADDR_IN6) };
        let bytes = unsafe { sin6.sin6_addr.u.Byte };
        let addr = Ipv6Addr::from(bytes);
        Some(match prefix {
            Some(p) => format!("{}/{}", addr, p),
            None => addr.to_string(),
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Open ports — TCP + UDP, IPv4 + IPv6
// ---------------------------------------------------------------------------

pub fn list_open_ports() -> Vec<OpenPort> {
    let mut out = Vec::new();
    out.extend(list_tcp4_ports());
    out.extend(list_tcp6_ports());
    out.extend(list_udp4_ports());
    out.extend(list_udp6_ports());
    out
}

fn list_tcp4_ports() -> Vec<OpenPort> {
    let Some(buf) = query_tcp_table_owner_pid(AF_INET.0 as u32) else { return Vec::new() };
    let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe {
        let base = std::ptr::addr_of!((*table).table) as *const MIB_TCPROW_OWNER_PID;
        std::slice::from_raw_parts(base, count)
    };
    let mut out = Vec::with_capacity(count);
    for row in rows {
        if row.dwState != TCP_STATE_LISTEN {
            continue;
        }
        out.push(OpenPort {
            protocol: "TCP".to_string(),
            local_addr: ipv4_from_le_u32(row.dwLocalAddr).to_string(),
            local_port: be16_from_u32(row.dwLocalPort),
            state: "LISTEN".to_string(),
            pid: Some(row.dwOwningPid),
            ..Default::default()
        });
    }
    out
}

fn list_tcp6_ports() -> Vec<OpenPort> {
    let Some(buf) = query_tcp_table_owner_pid(AF_INET6.0 as u32) else { return Vec::new() };
    let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe {
        let base = std::ptr::addr_of!((*table).table) as *const MIB_TCP6ROW_OWNER_PID;
        std::slice::from_raw_parts(base, count)
    };
    let mut out = Vec::with_capacity(count);
    for row in rows {
        if row.dwState != TCP_STATE_LISTEN {
            continue;
        }
        out.push(OpenPort {
            protocol: "TCP6".to_string(),
            local_addr: Ipv6Addr::from(row.ucLocalAddr).to_string(),
            local_port: be16_from_u32(row.dwLocalPort),
            state: "LISTEN".to_string(),
            pid: Some(row.dwOwningPid),
            ..Default::default()
        });
    }
    out
}

fn list_udp4_ports() -> Vec<OpenPort> {
    let Some(buf) = query_udp_table_owner_pid(AF_INET.0 as u32) else { return Vec::new() };
    let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe {
        let base = std::ptr::addr_of!((*table).table) as *const MIB_UDPROW_OWNER_PID;
        std::slice::from_raw_parts(base, count)
    };
    let mut out = Vec::with_capacity(count);
    for row in rows {
        out.push(OpenPort {
            protocol: "UDP".to_string(),
            local_addr: ipv4_from_le_u32(row.dwLocalAddr).to_string(),
            local_port: be16_from_u32(row.dwLocalPort),
            state: "LISTEN".to_string(),
            pid: Some(row.dwOwningPid),
            ..Default::default()
        });
    }
    out
}

fn list_udp6_ports() -> Vec<OpenPort> {
    let Some(buf) = query_udp_table_owner_pid(AF_INET6.0 as u32) else { return Vec::new() };
    let table = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe {
        let base = std::ptr::addr_of!((*table).table) as *const MIB_UDP6ROW_OWNER_PID;
        std::slice::from_raw_parts(base, count)
    };
    let mut out = Vec::with_capacity(count);
    for row in rows {
        out.push(OpenPort {
            protocol: "UDP6".to_string(),
            local_addr: Ipv6Addr::from(row.ucLocalAddr).to_string(),
            local_port: be16_from_u32(row.dwLocalPort),
            state: "LISTEN".to_string(),
            pid: Some(row.dwOwningPid),
            ..Default::default()
        });
    }
    out
}

fn query_tcp_table_owner_pid(family: u32) -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    let _ = unsafe {
        GetExtendedTcpTable(None, &mut size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
    };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut size,
            false,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if rc != NO_ERROR.0 {
        return None;
    }
    Some(buf)
}

fn query_udp_table_owner_pid(family: u32) -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    let _ = unsafe {
        GetExtendedUdpTable(None, &mut size, false, family, UDP_TABLE_OWNER_PID, 0)
    };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut size,
            false,
            family,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if rc != NO_ERROR.0 {
        return None;
    }
    Some(buf)
}

fn ipv4_from_le_u32(v: u32) -> Ipv4Addr {
    // dwLocalAddr is stored in the same byte order as an IPv4 packet header (network / big-endian).
    let bytes = v.to_ne_bytes();
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn be16_from_u32(v: u32) -> u16 {
    // Ports in the MIB tables are stored as 4 bytes but only the low 2 bytes carry the port,
    // in network byte order (big-endian).
    let bytes = v.to_ne_bytes();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

// ---------------------------------------------------------------------------
// Firewall — read the values Windows Firewall itself persists in the registry.
// ---------------------------------------------------------------------------

pub fn get_firewall_profiles() -> Vec<FirewallProfile> {
    // (registry-suffix, display name emitted in the report / consumed by analyzers)
    let profiles = [
        ("DomainProfile", "Domain"),
        ("StandardProfile", "Private"),
        ("PublicProfile", "Public"),
    ];
    profiles
        .iter()
        .filter_map(|(subkey, display)| read_firewall_profile(subkey, display))
        .collect()
}

fn read_firewall_profile(subkey: &str, display_name: &str) -> Option<FirewallProfile> {
    let path = format!(
        r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{}",
        subkey
    );
    // The firewall service creates these keys on install, so absence means we can't
    // read them (permissions, or an unusual SKU). Filter with `?` — the analyzer's
    // "no data" path will fire.
    let enabled = registry::read_reg_dword(&path, "EnableFirewall")? != 0;
    let inbound = firewall_action_string(registry::read_reg_dword(&path, "DefaultInboundAction"));
    let outbound = firewall_action_string(registry::read_reg_dword(&path, "DefaultOutboundAction"));
    Some(FirewallProfile {
        name: display_name.to_string(),
        enabled,
        inbound_default: inbound,
        outbound_default: outbound,
    })
}

fn firewall_action_string(v: Option<u32>) -> String {
    // Semantics documented on NET_FW_ACTION: 0 = Block, 1 = Allow.
    // When the value is missing, Windows Firewall defaults to Block for inbound
    // and Allow for outbound. We report "Block" as the safe conservative default
    // because the analyzers key off the "allow" case.
    match v {
        Some(0) => "Block".to_string(),
        Some(1) => "Allow".to_string(),
        Some(_) => "Unknown".to_string(),
        None => "Block".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pwstr_to_string_lossy(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_action_maps_zero_to_block() {
        assert_eq!(firewall_action_string(Some(0)), "Block");
    }

    #[test]
    fn firewall_action_maps_one_to_allow() {
        assert_eq!(firewall_action_string(Some(1)), "Allow");
    }

    #[test]
    fn firewall_action_defaults_missing_to_block() {
        assert_eq!(firewall_action_string(None), "Block");
    }

    #[test]
    fn be16_extracts_network_order_port() {
        // 0xA1F1 stored little-endian in the low bytes of a u32 = big-endian port 41457.
        let raw = u32::from_ne_bytes([0xA1, 0xF1, 0, 0]);
        assert_eq!(be16_from_u32(raw), 0xA1F1);
    }
}
