// Windows registry helpers — compiled only on Windows.
// These are stubs until the Windows-specific implementation is filled in.

#[allow(dead_code)]
pub fn read_reg_dword(_path: &str, _value: &str) -> Option<u32> {
    unimplemented!("registry access not yet implemented")
}

#[allow(dead_code)]
pub fn read_reg_string(_path: &str, _value: &str) -> Option<String> {
    unimplemented!("registry access not yet implemented")
}
