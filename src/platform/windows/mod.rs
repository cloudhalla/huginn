// Windows platform implementation.
// All functions here are stubs pending the full Windows API integration.

pub mod registry;

use crate::error::HuginnError;
use crate::models::system_info::*;

pub fn collect_system_info(os: &mut OsInfo) -> Result<(), HuginnError> {
    os.architecture = std::env::consts::ARCH.to_string();
    // TODO: use RtlGetVersion / GetComputerNameExW / NetGetJoinInformation
    Ok(())
}

pub fn collect_users(users: &mut UserInfo) -> Result<(), HuginnError> {
    // TODO: use NetUserEnum / NetLocalGroupGetMembers / LsaQueryInformationPolicy
    let _ = users;
    Ok(())
}

pub fn collect_services(services: &mut ServicesInfo) -> Result<(), HuginnError> {
    // TODO: use OpenSCManager / EnumServicesStatusEx
    let _ = services;
    Ok(())
}

pub fn collect_network(net: &mut NetworkInfo) -> Result<(), HuginnError> {
    // TODO: use GetAdaptersInfo / GetExtendedTcpTable / NetFwPolicy2
    let _ = net;
    Ok(())
}

pub fn collect_security_policies(security: &mut SecurityPolicies) -> Result<(), HuginnError> {
    // TODO: read UAC, LSA protection, Defender status from registry
    let _ = security;
    Ok(())
}

pub fn collect_software(software: &mut SoftwareInfo) -> Result<(), HuginnError> {
    // TODO: enumerate HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    let _ = software;
    Ok(())
}

pub fn collect_scheduled_tasks(tasks: &mut ScheduledTasksInfo) -> Result<(), HuginnError> {
    // TODO: use ITaskService COM interface
    let _ = tasks;
    Ok(())
}
