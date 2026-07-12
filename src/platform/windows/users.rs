use std::ffi::c_void;
use std::process::Command;

use chrono::{DateTime, TimeZone, Utc};
use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::Win32::NetworkManagement::NetManagement::{
    FILTER_NORMAL_ACCOUNT, LOCALGROUP_MEMBERS_INFO_3, NetApiBufferFree, NetLocalGroupGetMembers,
    NetUserEnum, NetUserModalsGet, USER_INFO_2, USER_MODALS_INFO_0, USER_MODALS_INFO_3,
};

const NERR_SUCCESS: u32 = 0;
use windows::Win32::Security::{
    CreateWellKnownSid, LookupAccountSidW, PSID, SID_NAME_USE, WinBuiltinAdministratorsSid,
};
use windows::core::{PCWSTR, PWSTR};

use crate::error::HuginnError;
use crate::models::system_info::{LocalUser, LockoutPolicy, PasswordPolicy, UserInfo};

// User flag bits (see lmaccess.h)
const UF_ACCOUNTDISABLE: u32 = 0x0002;
const UF_PASSWD_NOTREQD: u32 = 0x0020;
const UF_DONT_EXPIRE_PASSWD: u32 = 0x10000;

// Sentinel: "never expires" / "no maximum".
const TIMEQ_FOREVER: u32 = u32::MAX;

pub fn collect(users: &mut UserInfo) -> Result<(), HuginnError> {
    users.password_policy = read_password_policy();
    users.lockout_policy = read_lockout_policy();
    users.admin_group_members = read_admin_group_members();
    users.users = read_local_users(&users.admin_group_members);

    // Optional supplement for complexity_required / reversible_encryption via secedit.
    // If not admin (or secedit fails), the fields stay None and the analyzer will
    // emit a "data unavailable" skip finding for CIS-1.1.4 / CIS-1.1.5.
    if let Some((complexity, reversible)) = read_secedit_password_flags() {
        users.password_policy.complexity_required = Some(complexity);
        users.password_policy.reversible_encryption = Some(reversible);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Password / lockout policy — NetUserModalsGet
// ---------------------------------------------------------------------------

fn read_password_policy() -> PasswordPolicy {
    let mut policy = PasswordPolicy::default();
    let Some(guard) = NetApiBuffer::query(0) else {
        return policy;
    };
    let info = unsafe { &*(guard.ptr as *const USER_MODALS_INFO_0) };

    policy.min_length = Some(info.usrmod0_min_passwd_len);
    policy.max_age_days = Some(seconds_to_days_or_zero(info.usrmod0_max_passwd_age));
    policy.min_age_days = Some(info.usrmod0_min_passwd_age / 86400);
    policy.history_count = Some(info.usrmod0_password_hist_len);
    policy
}

fn read_lockout_policy() -> LockoutPolicy {
    let mut policy = LockoutPolicy::default();
    let Some(guard) = NetApiBuffer::query(3) else {
        return policy;
    };
    let info = unsafe { &*(guard.ptr as *const USER_MODALS_INFO_3) };

    policy.threshold = Some(info.usrmod3_lockout_threshold);
    policy.duration_minutes = Some(if info.usrmod3_lockout_duration == TIMEQ_FOREVER {
        0
    } else {
        info.usrmod3_lockout_duration / 60
    });
    policy.observation_window_minutes = Some(info.usrmod3_lockout_observation_window / 60);
    policy
}

fn seconds_to_days_or_zero(s: u32) -> u32 {
    if s == TIMEQ_FOREVER { 0 } else { s / 86400 }
}

// ---------------------------------------------------------------------------
// Local user enumeration — NetUserEnum
// ---------------------------------------------------------------------------

fn read_local_users(admin_members: &[String]) -> Vec<LocalUser> {
    let mut users = Vec::new();
    let mut resume_handle: u32 = 0;

    loop {
        let mut buf_ptr: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let rc = unsafe {
            NetUserEnum(
                PCWSTR::null(),
                2,
                FILTER_NORMAL_ACCOUNT,
                &mut buf_ptr,
                u32::MAX, // let the API pick a size
                &mut entries_read,
                &mut total_entries,
                Some(&mut resume_handle),
            )
        };

        if buf_ptr.is_null() {
            break;
        }

        if rc == NERR_SUCCESS || rc == ERROR_MORE_DATA.0 {
            let entries =
                unsafe { std::slice::from_raw_parts(buf_ptr as *const USER_INFO_2, entries_read as usize) };
            for e in entries {
                if let Some(u) = user_from_info2(e, admin_members) {
                    users.push(u);
                }
            }
        }

        unsafe {
            let _ = NetApiBufferFree(Some(buf_ptr as *const c_void));
        }

        if rc != ERROR_MORE_DATA.0 {
            break;
        }
    }
    users
}

fn user_from_info2(info: &USER_INFO_2, admin_members: &[String]) -> Option<LocalUser> {
    let username = pwstr_to_string(info.usri2_name)?;
    let full_name = pwstr_to_string(info.usri2_full_name).filter(|s| !s.is_empty());
    let flags = info.usri2_flags.0;

    let enabled = flags & UF_ACCOUNTDISABLE == 0;
    let password_required = flags & UF_PASSWD_NOTREQD == 0;
    let password_expires = flags & UF_DONT_EXPIRE_PASSWD == 0;
    let last_logon = unix_secs_to_dt(info.usri2_last_logon);
    let password_last_set = if info.usri2_password_age > 0 {
        let now = Utc::now().timestamp();
        unix_secs_to_dt((now - info.usri2_password_age as i64).max(0) as u32)
    } else {
        None
    };
    let is_admin = admin_members
        .iter()
        .any(|m| m.rsplit('\\').next().unwrap_or(m).eq_ignore_ascii_case(&username));

    Some(LocalUser {
        username,
        full_name,
        sid: None, // deferred — not gating any analyzer
        uid: None,
        enabled,
        password_required,
        password_expires,
        password_last_set,
        last_logon,
        groups: Vec::new(), // deferred
        is_admin,
    })
}

fn unix_secs_to_dt(secs: u32) -> Option<DateTime<Utc>> {
    if secs == 0 {
        return None;
    }
    Utc.timestamp_opt(secs as i64, 0).single()
}

// ---------------------------------------------------------------------------
// Administrators group members — CreateWellKnownSid + LookupAccountSidW +
//                                NetLocalGroupGetMembers
// ---------------------------------------------------------------------------

fn read_admin_group_members() -> Vec<String> {
    let Some(admin_group) = resolve_admin_group_name() else {
        return Vec::new();
    };
    let mut members = Vec::new();
    let mut resume_handle: usize = 0;
    let admin_w = to_wide_null(&admin_group);

    loop {
        let mut buf_ptr: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let rc = unsafe {
            NetLocalGroupGetMembers(
                PCWSTR::null(),
                PCWSTR(admin_w.as_ptr()),
                3,
                &mut buf_ptr,
                u32::MAX,
                &mut entries_read,
                &mut total_entries,
                Some(&mut resume_handle),
            )
        };

        if buf_ptr.is_null() {
            break;
        }

        if rc == NERR_SUCCESS || rc == ERROR_MORE_DATA.0 {
            let entries = unsafe {
                std::slice::from_raw_parts(
                    buf_ptr as *const LOCALGROUP_MEMBERS_INFO_3,
                    entries_read as usize,
                )
            };
            for e in entries {
                if let Some(name) = pwstr_to_string(e.lgrmi3_domainandname) {
                    members.push(name);
                }
            }
        }

        unsafe {
            let _ = NetApiBufferFree(Some(buf_ptr as *const c_void));
        }

        if rc != ERROR_MORE_DATA.0 {
            break;
        }
    }
    members
}

fn resolve_admin_group_name() -> Option<String> {
    // Build the well-known BUILTIN\Administrators SID.
    let mut sid_buf = [0u8; 256];
    let mut sid_size = sid_buf.len() as u32;
    let sid = PSID(sid_buf.as_mut_ptr() as *mut _);
    unsafe {
        CreateWellKnownSid(WinBuiltinAdministratorsSid, None, sid, &mut sid_size).ok()?;
    }

    // Look up the localized account name for that SID.
    let mut name_buf = [0u16; 256];
    let mut name_len = name_buf.len() as u32;
    let mut domain_buf = [0u16; 256];
    let mut domain_len = domain_buf.len() as u32;
    let mut use_type = SID_NAME_USE::default();
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            PWSTR(name_buf.as_mut_ptr()),
            &mut name_len,
            PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_len,
            &mut use_type,
        )
        .ok()?;
    }
    Some(String::from_utf16_lossy(&name_buf[..name_len as usize]))
}

// ---------------------------------------------------------------------------
// secedit fallback for complexity_required / reversible_encryption
// ---------------------------------------------------------------------------

fn read_secedit_password_flags() -> Option<(bool, bool)> {
    // secedit writes UTF-16 LE INI file. Use a temp path.
    let temp = std::env::temp_dir().join(format!("huginn-secedit-{}.inf", std::process::id()));
    let temp_str = temp.to_str()?;

    let out = Command::new("secedit")
        .args([
            "/export",
            "/cfg",
            temp_str,
            "/areas",
            "SECURITYPOLICY",
            "/quiet",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&temp);
        return None;
    }

    let raw = std::fs::read(&temp).ok();
    let _ = std::fs::remove_file(&temp);
    let raw = raw?;
    let text = decode_secedit(&raw);

    let mut complexity: Option<bool> = None;
    let mut cleartext: Option<bool> = None;
    let mut in_sys_access = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_sys_access = line.eq_ignore_ascii_case("[System Access]");
            continue;
        }
        if !in_sys_access {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("PasswordComplexity") {
                complexity = val.parse::<u32>().ok().map(|n| n != 0);
            } else if key.eq_ignore_ascii_case("ClearTextPassword") {
                cleartext = val.parse::<u32>().ok().map(|n| n != 0);
            }
        }
    }
    match (complexity, cleartext) {
        (Some(c), Some(r)) => Some((c, r)),
        _ => None,
    }
}

fn decode_secedit(raw: &[u8]) -> String {
    // secedit /export writes UTF-16 LE with a BOM.
    if raw.len() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
        let u16s: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    }
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
        let slice = std::slice::from_raw_parts(p.0, len);
        Some(String::from_utf16_lossy(slice))
    }
}

/// RAII wrapper around a `NetUserModalsGet` result buffer.
struct NetApiBuffer {
    ptr: *mut u8,
}

impl NetApiBuffer {
    fn query(level: u32) -> Option<Self> {
        let mut buf_ptr: *mut u8 = std::ptr::null_mut();
        let rc = unsafe { NetUserModalsGet(PCWSTR::null(), level, &mut buf_ptr) };
        if rc != NERR_SUCCESS || buf_ptr.is_null() {
            return None;
        }
        Some(Self { ptr: buf_ptr })
    }
}

impl Drop for NetApiBuffer {
    fn drop(&mut self) {
        unsafe {
            let _ = NetApiBufferFree(Some(self.ptr as *const c_void));
        }
    }
}
