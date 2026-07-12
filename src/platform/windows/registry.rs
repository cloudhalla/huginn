use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_DWORD,
    REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};
use windows::core::PCWSTR;

struct HKeyGuard(HKEY);

impl Drop for HKeyGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn split_root(path: &str) -> Option<(HKEY, &str)> {
    let (root, subkey) = path.split_once('\\')?;
    let hkey = match root {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        _ => return None,
    };
    Some((hkey, subkey))
}

fn open_key(path: &str) -> Option<HKeyGuard> {
    let (root, subkey) = split_root(path)?;
    let sub_w = to_wide_null(subkey);
    let mut handle = HKEY::default();
    let rc: WIN32_ERROR = unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(sub_w.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut handle,
        )
    };
    if rc == ERROR_SUCCESS {
        Some(HKeyGuard(handle))
    } else {
        None
    }
}

pub fn read_reg_dword(path: &str, value: &str) -> Option<u32> {
    let guard = open_key(path)?;
    let value_w = to_wide_null(value);
    let mut ty = REG_VALUE_TYPE::default();
    let mut data = [0u8; 4];
    let mut size = data.len() as u32;
    let rc: WIN32_ERROR = unsafe {
        RegQueryValueExW(
            guard.0,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut ty),
            Some(data.as_mut_ptr()),
            Some(&mut size),
        )
    };
    if rc != ERROR_SUCCESS || ty != REG_DWORD || size < 4 {
        return None;
    }
    Some(u32::from_le_bytes(data))
}

pub fn read_reg_string(path: &str, value: &str) -> Option<String> {
    let guard = open_key(path)?;
    let value_w = to_wide_null(value);

    let mut ty = REG_VALUE_TYPE::default();
    let mut size: u32 = 0;
    let rc: WIN32_ERROR = unsafe {
        RegQueryValueExW(
            guard.0,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut ty),
            None,
            Some(&mut size),
        )
    };
    if rc != ERROR_SUCCESS || (ty != REG_SZ && ty != REG_EXPAND_SZ) || size == 0 {
        return None;
    }

    let mut buf = vec![0u16; size.div_ceil(2) as usize];
    let mut size2 = size;
    let rc: WIN32_ERROR = unsafe {
        RegQueryValueExW(
            guard.0,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut size2),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }

    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}
