use crate::error::HuginnError;
use crate::models::{finding::Finding, system_info::SystemInfo};

pub mod cis;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsTarget {
    Windows,
    Linux,
    Any,
}

impl OsTarget {
    fn matches_current(&self) -> bool {
        match self {
            OsTarget::Any => true,
            OsTarget::Windows => std::env::consts::OS == "windows",
            OsTarget::Linux => std::env::consts::OS == "linux",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            OsTarget::Windows => "windows",
            OsTarget::Linux => "linux",
            OsTarget::Any => "any",
        }
    }
}

pub trait Analyzer: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn target_os(&self) -> OsTarget { OsTarget::Any }
    fn analyze(&self, info: &SystemInfo) -> Result<Vec<Finding>, HuginnError>;
}

pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl AnalyzerRegistry {
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
        }
    }

    pub fn register(mut self, a: impl Analyzer + 'static) -> Self {
        self.analyzers.push(Box::new(a));
        self
    }

    pub fn run_all(&self, info: &SystemInfo, progress: &dyn Fn(&str)) -> Vec<Finding> {
        let mut findings = Vec::new();
        for analyzer in &self.analyzers {
            if !analyzer.target_os().matches_current() {
                continue;
            }
            progress(&format!("  [{:20}] {}", analyzer.id(), analyzer.name()));
            let os_label = analyzer.target_os().label().to_string();
            match analyzer.analyze(info) {
                Ok(mut f) => {
                    for finding in &mut f {
                        finding.os_target = os_label.clone();
                    }
                    findings.append(&mut f);
                }
                Err(e) => {
                    eprintln!("    Warning: analyzer '{}' failed: {}", analyzer.id(), e)
                }
            }
        }
        findings
    }
}
