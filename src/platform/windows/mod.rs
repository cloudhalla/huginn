pub mod registry;
mod software;
mod users;

use crate::error::HuginnError;
use crate::models::system_info::*;

use windows::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetApiBufferFree, NetGetJoinInformation, NetSetupDomainName,
};
use windows::Win32::System::SystemInformation::{
    ComputerNameDnsHostname, GetComputerNameExW, GetTickCount64,
};
use windows::core::{PCWSTR, PWSTR};

pub fn collect_system_info(os: &mut OsInfo) -> Result<(), HuginnError> {
    os.architecture = std::env::consts::ARCH.to_string();
    os.hostname = get_dns_hostname().unwrap_or_default();
    fill_os_version(os);
    os.uptime_seconds = unsafe { GetTickCount64() } / 1000;
    os.domain = get_domain_name();
    Ok(())
}

pub fn collect_users(u: &mut UserInfo) -> Result<(), HuginnError> {
    users::collect(u)
}

pub fn collect_services(services: &mut ServicesInfo) -> Result<(), HuginnError> {
    // Tier 2: OpenSCManager / EnumServicesStatusEx
    let _ = services;
    Ok(())
}

pub fn collect_network(net: &mut NetworkInfo) -> Result<(), HuginnError> {
    // Tier 2: GetAdaptersInfo / GetExtendedTcpTable / NetFwPolicy2
    let _ = net;
    Ok(())
}

pub fn collect_security_policies(security: &mut SecurityPolicies) -> Result<(), HuginnError> {
    let uac_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    security.uac_enabled = registry::read_reg_dword(uac_key, "EnableLUA").map(|v| v != 0);
    security.uac_level = registry::read_reg_dword(uac_key, "ConsentPromptBehaviorAdmin");
    security.secure_desktop =
        registry::read_reg_dword(uac_key, "PromptOnSecureDesktop").map(|v| v != 0);

    let lsa_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
    security.lsa_protection = registry::read_reg_dword(lsa_key, "RunAsPPL").map(|v| v != 0);
    security.credential_guard = registry::read_reg_dword(lsa_key, "LsaCfgFlags").map(|v| v != 0);

    let defender_key = r"HKLM\SOFTWARE\Microsoft\Windows Defender";
    security.defender_enabled = Some(
        registry::read_reg_dword(defender_key, "DisableAntiSpyware")
            .map(|v| v == 0)
            .unwrap_or(true),
    );
    let defender_rt_key = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
    security.defender_real_time = Some(
        registry::read_reg_dword(defender_rt_key, "DisableRealtimeMonitoring")
            .map(|v| v == 0)
            .unwrap_or(true),
    );

    let smb_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    security.smb_v1_enabled = Some(
        registry::read_reg_dword(smb_key, "SMB1")
            .map(|v| v != 0)
            .unwrap_or(true),
    );

    Ok(())
}

pub fn collect_software(sw: &mut SoftwareInfo) -> Result<(), HuginnError> {
    software::collect(sw)
}

pub fn collect_scheduled_tasks(tasks: &mut ScheduledTasksInfo) -> Result<(), HuginnError> {
    // Tier 2: ITaskService COM interface
    let _ = tasks;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_dns_hostname() -> Option<String> {
    let mut size: u32 = 0;
    // First call sizes the buffer (returns Err with `size` set to required length in wchars,
    // including the terminating null).
    let _ = unsafe { GetComputerNameExW(ComputerNameDnsHostname, PWSTR::null(), &mut size) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u16; size as usize];
    let mut size2 = size;
    unsafe { GetComputerNameExW(ComputerNameDnsHostname, PWSTR(buf.as_mut_ptr()), &mut size2) }
        .ok()?;
    let len = size2 as usize;
    let end = buf.iter().take(len).position(|&c| c == 0).unwrap_or(len);
    Some(String::from_utf16_lossy(&buf[..end]))
}

fn fill_os_version(os: &mut OsInfo) {
    let cv = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product_name = registry::read_reg_string(cv, "ProductName");
    let major = registry::read_reg_dword(cv, "CurrentMajorVersionNumber");
    let minor = registry::read_reg_dword(cv, "CurrentMinorVersionNumber");
    let build_str = registry::read_reg_string(cv, "CurrentBuild")
        .or_else(|| registry::read_reg_string(cv, "CurrentBuildNumber"));
    let display = registry::read_reg_string(cv, "DisplayVersion");

    let build_num: Option<u32> = build_str.as_deref().and_then(|s| s.parse().ok());
    let is_win11 = build_num.map(|b| b >= 22000).unwrap_or(false);

    // Windows 11 still ships ProductName = "Windows 10 …" for compatibility; patch it up.
    os.name = match product_name {
        Some(n) if is_win11 => n.replacen("Windows 10", "Windows 11", 1),
        Some(n) => n,
        None => "Windows".to_string(),
    };

    os.version = match (major, minor, build_str.as_deref(), display.as_deref()) {
        (Some(mj), Some(mn), Some(b), Some(d)) => format!("{}.{}.{} ({})", mj, mn, b, d),
        (Some(mj), Some(mn), Some(b), None) => format!("{}.{}.{}", mj, mn, b),
        (_, _, Some(b), Some(d)) => format!("{} ({})", b, d),
        (_, _, Some(b), None) => b.to_string(),
        _ => String::new(),
    };

    os.build = build_str;
}

fn get_domain_name() -> Option<String> {
    let mut name_ptr = PWSTR::null();
    let mut status = Default::default();
    let rc =
        unsafe { NetGetJoinInformation(PCWSTR::null(), &mut name_ptr, &mut status) };
    if rc != NERR_Success {
        return None;
    }

    let result = if status == NetSetupDomainName && !name_ptr.is_null() {
        let mut len = 0usize;
        // SAFETY: NetGetJoinInformation returns a null-terminated wide string on success.
        unsafe {
            while *name_ptr.0.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(name_ptr.0, len);
            Some(String::from_utf16_lossy(slice))
        }
    } else {
        None
    };

    if !name_ptr.is_null() {
        unsafe {
            let _ = NetApiBufferFree(Some(name_ptr.0 as *const _));
        }
    }

    result
}
