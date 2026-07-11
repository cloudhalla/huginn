use crate::collectors::Collector;
use crate::error::HuginnError;
use crate::models::system_info::SystemInfo;

pub struct SecurityPoliciesCollector;

impl Collector for SecurityPoliciesCollector {
    fn name(&self) -> &'static str {
        "security_policies"
    }

    fn description(&self) -> &'static str {
        "UAC, LSA, audit policies, Defender, SMBv1, RDP"
    }

    fn requires_elevation(&self) -> bool {
        true
    }

    fn collect(&self, info: &mut SystemInfo) -> Result<(), HuginnError> {
        crate::platform::os::collect_security_policies(&mut info.security)
    }
}
