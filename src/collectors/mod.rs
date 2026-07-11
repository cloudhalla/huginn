use crate::error::HuginnError;
use crate::models::system_info::SystemInfo;

pub mod network;
pub mod scheduled_tasks;
pub mod security_policies;
pub mod services;
pub mod software;
pub mod system_info;
pub mod users;

pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    #[allow(dead_code)]
    fn requires_elevation(&self) -> bool {
        false
    }
    fn collect(&self, info: &mut SystemInfo) -> Result<(), HuginnError>;
}

pub struct CollectorRegistry {
    collectors: Vec<Box<dyn Collector>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        Self {
            collectors: Vec::new(),
        }
    }

    pub fn register(mut self, c: impl Collector + 'static) -> Self {
        self.collectors.push(Box::new(c));
        self
    }

    pub fn filtered(self, names: Option<&[String]>) -> Self {
        match names {
            None => self,
            Some(filter) => Self {
                collectors: self
                    .collectors
                    .into_iter()
                    .filter(|c| filter.iter().any(|n| n == c.name()))
                    .collect(),
            },
        }
    }

    pub fn run_all(&self, progress: &dyn Fn(&str)) -> Result<SystemInfo, HuginnError> {
        let mut info = SystemInfo::default();
        info.collected_at = Some(chrono::Utc::now());

        for collector in &self.collectors {
            progress(&format!(
                "  [{:20}] {}",
                collector.name(),
                collector.description()
            ));
            if let Err(e) = collector.collect(&mut info) {
                eprintln!("    Warning: {}", e);
            }
        }

        Ok(info)
    }
}
