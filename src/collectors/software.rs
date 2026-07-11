use crate::collectors::Collector;
use crate::error::HuginnError;
use crate::models::system_info::SystemInfo;

pub struct SoftwareCollector;

impl Collector for SoftwareCollector {
    fn name(&self) -> &'static str {
        "software"
    }

    fn description(&self) -> &'static str {
        "Installed software, AV/EDR products, hotfixes"
    }

    fn collect(&self, info: &mut SystemInfo) -> Result<(), HuginnError> {
        crate::platform::os::collect_software(&mut info.software)
    }
}
