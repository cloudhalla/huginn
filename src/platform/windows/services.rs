use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{ERROR_MORE_DATA, LocalFree, HLOCAL, WIN32_ERROR};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
    PSECURITY_DESCRIPTOR, PSID, WELL_KNOWN_SID_TYPE,
    WinAnonymousSid, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid, WinWorldSid,
};
use windows::Win32::System::Services::{
    ENUM_SERVICE_STATUS_PROCESSW, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED,
    SERVICE_PAUSED, SERVICE_QUERY_CONFIG, SERVICE_RUNNING, SERVICE_STATE_ALL, SERVICE_STOPPED,
    SERVICE_WIN32, EnumServicesStatusExW,
};
use windows::core::{Free, PCWSTR, PWSTR};

use crate::error::HuginnError;
use crate::models::system_info::{ServiceInfo, ServiceStartType, ServiceState, ServicesInfo};

// File access rights we treat as "write" for weak-ACL detection.
// Kept as local constants to avoid pulling in Win32_Storage_FileSystem.
// Note: we deliberately don't include FILE_ALL_ACCESS here — its bit
// pattern includes READ_CONTROL and SYNCHRONIZE, which are set by
// FILE_GENERIC_READ too, so mixing it in would false-flag every ACE
// that grants read access.
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const DANGEROUS_WRITE_MASK: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;

pub fn collect(services: &mut ServicesInfo) -> Result<(), HuginnError> {
    services.services = enumerate_services();
    Ok(())
}

fn enumerate_services() -> Vec<ServiceInfo> {
    let Ok(mut scm) = (unsafe {
        OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
    }) else {
        return Vec::new();
    };

    let out = enumerate_with_handle(scm);
    unsafe { scm.free() };
    out
}

fn enumerate_with_handle(scm: SC_HANDLE) -> Vec<ServiceInfo> {
    let mut results = Vec::new();
    let mut resume: u32 = 0;
    // Start with a moderately-sized buffer; EnumServicesStatusExW tells us how much more it needs.
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let mut bytes_needed: u32 = 0;
        let mut count: u32 = 0;

        let rc = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(buf.as_mut_slice()),
                &mut bytes_needed,
                &mut count,
                Some(&mut resume),
                PCWSTR::null(),
            )
        };

        let more_data = matches!(rc.as_ref().err().and_then(|e| WIN32_ERROR::from_error(e)), Some(ERROR_MORE_DATA));

        if rc.is_ok() || more_data {
            let entries = unsafe {
                std::slice::from_raw_parts(
                    buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    count as usize,
                )
            };
            for e in entries {
                if let Some(svc) = build_service_info(scm, e) {
                    results.push(svc);
                }
            }
        }

        if more_data {
            // Grow if the API needs more room than the current buffer, and try again.
            if bytes_needed as usize > buf.len() {
                buf.resize(bytes_needed as usize, 0);
            }
            continue;
        }
        break;
    }
    results
}

fn build_service_info(scm: SC_HANDLE, entry: &ENUM_SERVICE_STATUS_PROCESSW) -> Option<ServiceInfo> {
    let name = pwstr_to_string(entry.lpServiceName)?;
    let display_name = pwstr_to_string(entry.lpDisplayName).unwrap_or_else(|| name.clone());
    let state = current_state_to_enum(entry.ServiceStatusProcess.dwCurrentState.0);

    let name_w = to_wide_null(&name);
    let Ok(mut svc) = (unsafe { OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_CONFIG) })
    else {
        return Some(ServiceInfo {
            name,
            display_name,
            state,
            ..Default::default()
        });
    };

    let (start_type, binary_path, run_as_account) = read_service_config(svc);
    unsafe { svc.free() };

    let extracted = binary_path.as_deref().and_then(extract_binary_path_from_imagepath);
    let unquoted_path = binary_path
        .as_deref()
        .map(is_unquoted_service_path)
        .unwrap_or(false);
    let weak_permissions = extracted
        .as_deref()
        .map(check_weak_file_acl)
        .unwrap_or(false);

    Some(ServiceInfo {
        name,
        display_name,
        state,
        start_type,
        binary_path,
        run_as_account,
        description: None,
        weak_permissions,
        unquoted_path,
    })
}

fn read_service_config(svc: SC_HANDLE) -> (ServiceStartType, Option<String>, Option<String>) {
    let mut bytes_needed: u32 = 0;
    // Probe size.
    let _ = unsafe { QueryServiceConfigW(svc, None, 0, &mut bytes_needed) };
    if bytes_needed == 0 {
        return (ServiceStartType::Unknown, None, None);
    }
    let mut buf = vec![0u8; bytes_needed as usize];
    let mut size = bytes_needed;
    let cfg_ptr = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    if unsafe { QueryServiceConfigW(svc, Some(cfg_ptr), buf.len() as u32, &mut size) }.is_err() {
        return (ServiceStartType::Unknown, None, None);
    }
    let cfg = unsafe { &*cfg_ptr };
    let start_type = start_type_to_enum(cfg.dwStartType.0);
    let binary_path = pwstr_to_string(cfg.lpBinaryPathName);
    let run_as_account = pwstr_to_string(cfg.lpServiceStartName);
    (start_type, binary_path, run_as_account)
}

fn start_type_to_enum(v: u32) -> ServiceStartType {
    match v {
        x if x == SERVICE_AUTO_START.0 => ServiceStartType::Automatic,
        x if x == SERVICE_DEMAND_START.0 => ServiceStartType::Manual,
        x if x == SERVICE_DISABLED.0 => ServiceStartType::Disabled,
        _ => ServiceStartType::Unknown,
    }
}

fn current_state_to_enum(v: u32) -> ServiceState {
    match v {
        x if x == SERVICE_RUNNING.0 => ServiceState::Running,
        x if x == SERVICE_STOPPED.0 => ServiceState::Stopped,
        x if x == SERVICE_PAUSED.0 => ServiceState::Paused,
        _ => ServiceState::Unknown,
    }
}

// ---------------------------------------------------------------------------
// ImagePath parsing
// ---------------------------------------------------------------------------

/// Pull a filesystem path out of a service's `ImagePath` value.
///
/// Handles: `"C:\path with spaces\svc.exe" --arg`, `C:\path\svc.exe -k netsvcs`,
/// driver-style `\SystemRoot\System32\drivers\foo.sys`, and `\??\C:\...`.
/// Returns `None` for shell rundll32 stubs or entries we can't confidently
/// resolve to a real file.
pub(crate) fn extract_binary_path_from_imagepath(image_path: &str) -> Option<PathBuf> {
    let trimmed = image_path.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Quoted form: everything up to the closing quote is the path.
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return Some(PathBuf::from(&rest[..end]));
        }
        return None;
    }

    // Driver device paths — normalize to a real filesystem path.
    let normalized: String;
    let candidate = if let Some(rest) = trimmed.strip_prefix(r"\??\") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix(r"\SystemRoot\") {
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| String::from("C:\\Windows"));
        normalized = format!("{}\\{}", sysroot.trim_end_matches('\\'), rest);
        &normalized
    } else if trimmed.starts_with(r"System32\") || trimmed.starts_with(r"system32\") {
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| String::from("C:\\Windows"));
        normalized = format!("{}\\{}", sysroot.trim_end_matches('\\'), trimmed);
        &normalized
    } else {
        trimmed
    };

    // Unquoted form: the path runs up to the first argument. We can't tell
    // where the path ends without checking the filesystem, so use the "first
    // extension we recognize" heuristic — take everything up to (and including)
    // the first `.exe` / `.sys` / `.dll` token.
    for ext in [".exe", ".sys", ".dll", ".bat", ".cmd"] {
        if let Some(idx) = candidate.to_ascii_lowercase().find(ext) {
            let end = idx + ext.len();
            return Some(PathBuf::from(&candidate[..end]));
        }
    }

    // Fallback: split on first whitespace.
    let end = candidate.find(char::is_whitespace).unwrap_or(candidate.len());
    Some(PathBuf::from(&candidate[..end]))
}

/// True when the raw ImagePath value has spaces in the path portion but
/// isn't wrapped in double quotes — the classic "unquoted service path"
/// privilege-escalation pattern.
pub(crate) fn is_unquoted_service_path(image_path: &str) -> bool {
    let trimmed = image_path.trim();
    if trimmed.is_empty() || trimmed.starts_with('"') {
        return false;
    }
    // Drivers and \\?\ paths aren't affected by the classic hijack pattern.
    if trimmed.starts_with(r"\??\") || trimmed.starts_with(r"\SystemRoot\") {
        return false;
    }
    // Extract just the path (up to and including the first known extension)
    // and check whether that has whitespace.
    let lower = trimmed.to_ascii_lowercase();
    for ext in [".exe", ".sys", ".bat", ".cmd"] {
        if let Some(idx) = lower.find(ext) {
            let path = &trimmed[..idx + ext.len()];
            return path.contains(' ');
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Weak ACL detection
// ---------------------------------------------------------------------------

fn check_weak_file_acl(path: &Path) -> bool {
    let Some(path_str) = path.to_str() else { return false };
    if !path.exists() {
        return false;
    }
    let path_w = to_wide_null(path_str);

    let mut dacl_ptr: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();

    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl_ptr),
            None,
            &mut sd,
        )
    };
    if rc.is_err() || sd.0.is_null() {
        return false;
    }

    let weak = unsafe { dacl_grants_write_to_non_privileged(dacl_ptr) };

    unsafe {
        LocalFree(HLOCAL(sd.0));
    }

    weak
}

unsafe fn dacl_grants_write_to_non_privileged(dacl: *mut ACL) -> bool {
    if dacl.is_null() {
        return false;
    }
    let risky_sids = build_risky_sids();
    let ace_count = unsafe { (*dacl).AceCount } as u32;
    let mut cursor = unsafe { (dacl as *const u8).add(std::mem::size_of::<ACL>()) };

    for _ in 0..ace_count {
        let header = unsafe { &*(cursor as *const ACE_HEADER) };
        let ace_size = header.AceSize as usize;
        if ace_size == 0 {
            break;
        }
        if header.AceType == ACCESS_ALLOWED_ACE_TYPE {
            let ace = unsafe { &*(cursor as *const ACCESS_ALLOWED_ACE) };
            if ace.Mask & DANGEROUS_WRITE_MASK != 0 {
                let sid_ptr = &ace.SidStart as *const u32 as *const core::ffi::c_void;
                let psid = PSID(sid_ptr as *mut _);
                for risky in &risky_sids {
                    let risky_psid = PSID(risky.as_ptr() as *mut _);
                    if unsafe { EqualSid(psid, risky_psid) }.is_ok() {
                        return true;
                    }
                }
            }
        }
        cursor = unsafe { cursor.add(ace_size) };
    }
    false
}

fn build_risky_sids() -> Vec<Vec<u8>> {
    // Non-privileged principals that should not have write access to a service
    // binary. Anything Administrators / SYSTEM / TrustedInstaller / service SIDs
    // grants is expected — we're looking for the world-writable pattern.
    [
        WinWorldSid,               // Everyone
        WinAnonymousSid,           // Anonymous logon
        WinAuthenticatedUserSid,   // Authenticated Users
        WinInteractiveSid,         // Interactive
        WinBuiltinUsersSid,        // BUILTIN\Users
    ]
    .into_iter()
    .filter_map(build_well_known_sid)
    .collect()
}

fn build_well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 68]; // SECURITY_MAX_SID_SIZE
    let mut size = buf.len() as u32;
    let psid = PSID(buf.as_mut_ptr() as *mut _);
    unsafe { CreateWellKnownSid(kind, None, psid, &mut size).ok()? };
    buf.truncate(size as usize);
    Some(buf)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn pwstr_to_string(p: PWSTR) -> Option<String> {
    if p.0.is_null() {
        return None;
    }
    unsafe {
        let mut len = 0usize;
        while *p.0.add(len) != 0 {
            len += 1;
        }
        if len == 0 {
            return None;
        }
        let slice = std::slice::from_raw_parts(p.0, len);
        Some(String::from_utf16_lossy(slice))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquoted_path_with_space_flagged() {
        assert!(is_unquoted_service_path(r"C:\Program Files\Foo\bar.exe"));
    }

    #[test]
    fn quoted_path_with_space_not_flagged() {
        assert!(!is_unquoted_service_path(r#""C:\Program Files\Foo\bar.exe""#));
    }

    #[test]
    fn path_without_space_not_flagged() {
        assert!(!is_unquoted_service_path(r"C:\Windows\System32\svchost.exe -k netsvcs"));
    }

    #[test]
    fn driver_path_not_flagged() {
        assert!(!is_unquoted_service_path(r"\SystemRoot\System32\drivers\foo.sys"));
    }

    #[test]
    fn extract_quoted_binary_path() {
        let p = extract_binary_path_from_imagepath(r#""C:\Program Files\Foo\bar.exe" --flag"#);
        assert_eq!(p, Some(PathBuf::from(r"C:\Program Files\Foo\bar.exe")));
    }

    #[test]
    fn extract_unquoted_binary_path() {
        let p = extract_binary_path_from_imagepath(r"C:\Windows\System32\svchost.exe -k netsvcs");
        assert_eq!(p, Some(PathBuf::from(r"C:\Windows\System32\svchost.exe")));
    }

    #[test]
    fn extract_systemroot_driver_path() {
        let p = extract_binary_path_from_imagepath(r"\SystemRoot\System32\drivers\foo.sys");
        // Depends on %SystemRoot% at test time — just check the tail.
        let s = p.unwrap();
        let s = s.to_string_lossy().to_ascii_lowercase();
        assert!(s.ends_with(r"\system32\drivers\foo.sys"));
    }

    #[test]
    fn extract_nt_prefix_path() {
        let p = extract_binary_path_from_imagepath(r"\??\C:\ProgramData\Vendor\svc.exe");
        assert_eq!(p, Some(PathBuf::from(r"C:\ProgramData\Vendor\svc.exe")));
    }

    /// Set HUGINN_TEST_WEAK_ACL_FILE to the path of a file whose DACL grants
    /// write to a non-privileged principal — the test then asserts we detect it.
    /// Silently passes if the env var is unset so CI on clean machines still works.
    #[test]
    fn detects_weak_acl_on_test_fixture() {
        let Ok(path) = std::env::var("HUGINN_TEST_WEAK_ACL_FILE") else { return };
        assert!(
            check_weak_file_acl(Path::new(&path)),
            "expected weak-ACL detection to fire on {path}"
        );
    }
}
