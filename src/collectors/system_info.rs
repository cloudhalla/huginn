use crate::collectors::Collector;
use crate::error::HuginnError;
use crate::models::system_info::SystemInfo;

pub struct SystemInfoCollector;

impl Collector for SystemInfoCollector {
    fn name(&self) -> &'static str {
        "system_info"
    }

    fn description(&self) -> &'static str {
        "OS version, hostname, domain, uptime"
    }

    fn collect(&self, info: &mut SystemInfo) -> Result<(), HuginnError> {
        crate::platform::os::collect_system_info(&mut info.os)
    }
}
