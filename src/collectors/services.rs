use crate::collectors::Collector;
use crate::error::HuginnError;
use crate::models::system_info::SystemInfo;

pub struct ServicesCollector;

impl Collector for ServicesCollector {
    fn name(&self) -> &'static str {
        "services"
    }

    fn description(&self) -> &'static str {
        "Running services, start types, binary paths"
    }

    fn collect(&self, info: &mut SystemInfo) -> Result<(), HuginnError> {
        crate::platform::os::collect_services(&mut info.services)
    }
}
