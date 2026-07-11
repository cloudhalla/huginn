use crate::collectors::Collector;
use crate::error::HuginnError;
use crate::models::system_info::SystemInfo;

pub struct ScheduledTasksCollector;

impl Collector for ScheduledTasksCollector {
    fn name(&self) -> &'static str {
        "scheduled_tasks"
    }

    fn description(&self) -> &'static str {
        "Scheduled tasks and cron jobs"
    }

    fn collect(&self, info: &mut SystemInfo) -> Result<(), HuginnError> {
        crate::platform::os::collect_scheduled_tasks(&mut info.scheduled_tasks)
    }
}
