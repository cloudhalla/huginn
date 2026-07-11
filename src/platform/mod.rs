#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows as os;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as os;

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
compile_error!("huginn only supports Windows and Linux");
