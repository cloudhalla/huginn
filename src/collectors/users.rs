use crate::collectors::Collector;
use crate::error::HuginnError;
use crate::models::system_info::SystemInfo;

pub struct UsersCollector;

impl Collector for UsersCollector {
    fn name(&self) -> &'static str {
        "users"
    }

    fn description(&self) -> &'static str {
        "Local users, groups, password and lockout policies"
    }

    fn requires_elevation(&self) -> bool {
        true // /etc/shadow requires root on Linux
    }

    fn collect(&self, info: &mut SystemInfo) -> Result<(), HuginnError> {
        crate::platform::os::collect_users(&mut info.users)
    }
}
