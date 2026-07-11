pub mod etc;
pub mod network;
pub mod proc;
pub mod security;
pub mod services;

use crate::error::HuginnError;
use crate::models::system_info::*;

pub fn collect_system_info(os: &mut OsInfo) -> Result<(), HuginnError> {
    let release = etc::read_os_release();
    os.name = release
        .get("PRETTY_NAME")
        .or_else(|| release.get("NAME"))
        .cloned()
        .unwrap_or_else(|| "Linux".to_string());
    os.version = release.get("VERSION_ID").cloned().unwrap_or_default();
    os.architecture = std::env::consts::ARCH.to_string();

    // Hostname via nix gethostname
    use nix::unistd::gethostname;
    os.hostname = gethostname()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .unwrap_or_default()
                .trim()
                .to_string()
        });

    os.uptime_seconds = proc::read_uptime().unwrap_or(0);
    os.domain = etc::read_domain();

    Ok(())
}

pub fn collect_users(users: &mut UserInfo) -> Result<(), HuginnError> {
    users.users = etc::read_passwd_users();
    users.admin_group_members = etc::read_sudo_group();
    users.password_policy = etc::read_pam_password_policy();
    users.lockout_policy = etc::read_pam_lockout_policy();
    Ok(())
}

pub fn collect_services(services: &mut ServicesInfo) -> Result<(), HuginnError> {
    services.services = self::services::list_services();
    Ok(())
}

pub fn collect_network(net: &mut NetworkInfo) -> Result<(), HuginnError> {
    net.interfaces = network::list_interfaces();
    net.open_ports = network::list_open_ports();
    net.firewall_profiles = network::get_firewall_status();
    net.dns_servers = etc::read_dns_servers();
    net.dns_info = network::collect_dns_info();
    Ok(())
}

pub fn collect_security_policies(sec: &mut SecurityPolicies) -> Result<(), HuginnError> {
    sec.smb_v1_enabled = network::check_smb_v1();
    sec.ssh_config = security::read_ssh_config();
    sec.kernel_params = security::read_kernel_params();
    Ok(())
}

pub fn collect_software(software: &mut SoftwareInfo) -> Result<(), HuginnError> {
    let pkgs = etc::list_installed_packages();
    software.av_edr_products = pkgs
        .iter()
        .filter(|p| p.is_av_or_edr)
        .map(|p| p.name.clone())
        .collect();
    software.installed_software = pkgs;
    Ok(())
}

pub fn collect_scheduled_tasks(tasks: &mut ScheduledTasksInfo) -> Result<(), HuginnError> {
    tasks.tasks = etc::list_cron_jobs();
    Ok(())
}
