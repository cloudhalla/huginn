use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    pub architecture: String,
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub uptime_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_date: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_boot: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LocalUser {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    pub enabled: bool,
    pub password_required: bool,
    pub password_expires: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_last_set: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_logon: Option<DateTime<Utc>>,
    pub groups: Vec<String>,
    pub is_admin: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_age_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complexity_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reversible_encryption: Option<bool>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LockoutPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_minutes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_window_minutes: Option<u32>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub users: Vec<LocalUser>,
    pub admin_group_members: Vec<String>,
    pub password_policy: PasswordPolicy,
    pub lockout_policy: LockoutPolicy,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Running,
    Stopped,
    Paused,
    #[default]
    Unknown,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStartType {
    Automatic,
    AutomaticDelayed,
    Manual,
    Disabled,
    #[default]
    Unknown,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub state: ServiceState,
    pub start_type: ServiceStartType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_as_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub weak_permissions: bool,
    pub unquoted_path: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ServicesInfo {
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dhcp_enabled: bool,
    pub is_up: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FirewallProfile {
    pub name: String,
    pub enabled: bool,
    pub inbound_default: String,
    pub outbound_default: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetworkInterface>,
    pub open_ports: Vec<OpenPort>,
    pub firewall_profiles: Vec<FirewallProfile>,
    pub dns_servers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_settings: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SecurityPolicies {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uac_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uac_level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_desktop: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lsa_protection: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_guard: Option<bool>,
    pub audit_policies: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defender_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defender_real_time: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defender_last_update: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smb_v1_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdp_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdp_nla_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub powershell_script_block_logging: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub powershell_transcription: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitlocker_status: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct InstalledSoftware {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_location: Option<String>,
    pub is_av_or_edr: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PatchInfo {
    pub kb_id: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_on: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SoftwareInfo {
    pub installed_software: Vec<InstalledSoftware>,
    pub hotfixes: Vec<PatchInfo>,
    pub av_edr_products: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_update_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update_check: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run: Option<DateTime<Utc>>,
    pub hidden: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScheduledTasksInfo {
    pub tasks: Vec<ScheduledTask>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collected_at: Option<DateTime<Utc>>,
    pub os: OsInfo,
    pub users: UserInfo,
    pub services: ServicesInfo,
    pub network: NetworkInfo,
    pub security: SecurityPolicies,
    pub software: SoftwareInfo,
    pub scheduled_tasks: ScheduledTasksInfo,
}
