use crate::error::HuginnError;
use crate::models::{finding::Finding, system_info::SystemInfo};

pub mod cis;

pub trait Analyzer: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
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
            progress(&format!("  [{:20}] {}", analyzer.id(), analyzer.name()));
            match analyzer.analyze(info) {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => {
                    eprintln!("    Warning: analyzer '{}' failed: {}", analyzer.id(), e)
                }
            }
        }
        findings
    }
}
