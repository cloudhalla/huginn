use anyhow::Context;
use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::analyzers::AnalyzerRegistry;
use crate::cli::OutputFormat;
use crate::collectors::CollectorRegistry;
use crate::models::{report::Report, system_info::SystemInfo};
use crate::output;

pub struct RunnerConfig {
    pub output_dir: PathBuf,
    pub output_format: OutputFormat,
    pub quiet: bool,
    pub collectors: Option<Vec<String>>,
    pub include_passed: bool,
}

impl RunnerConfig {
    fn info(&self, msg: &str) {
        if !self.quiet {
            println!("{} {}", "[*]".cyan().bold(), msg);
        }
    }

    fn success(&self, msg: &str) {
        if !self.quiet {
            println!("{} {}", "[+]".green().bold(), msg);
        }
    }

    fn section(&self, msg: &str) {
        if !self.quiet {
            println!("\n{}", msg.bold());
        }
    }
}

pub fn run_full(config: &RunnerConfig) -> anyhow::Result<()> {
    config.section("Collecting system information...");

    let registry = build_collector_registry()
        .filtered(config.collectors.as_deref());

    let system_info = registry
        .run_all(&|msg| config.info(msg))
        .context("Collection failed")?;

    config.section("Running security analyzers...");

    let analyzers = build_analyzer_registry();
    let mut findings = analyzers.run_all(&system_info, &|msg| config.info(msg));

    if !config.include_passed {
        findings.retain(|f| !f.passed);
    }

    let report = Report::new(system_info, findings);

    config.section("Writing outputs...");
    write_outputs(&report, config)?;

    if !config.quiet {
        println!();
        println!(
            "  Assessment complete for {}",
            report.target_hostname.cyan().bold()
        );
        println!(
            "  Risk score: {}  |  {} critical  {} high  {} medium  {} low",
            report.summary.risk_score.to_string().bold(),
            report.summary.critical.to_string().red().bold(),
            report.summary.high.to_string().yellow().bold(),
            report.summary.medium.to_string().yellow(),
            report.summary.low.to_string().blue(),
        );
    }

    Ok(())
}

pub fn run_collect_only(config: &RunnerConfig) -> anyhow::Result<()> {
    config.section("Collecting system information...");

    let registry = build_collector_registry()
        .filtered(config.collectors.as_deref());

    let system_info = registry
        .run_all(&|msg| config.info(msg))
        .context("Collection failed")?;

    std::fs::create_dir_all(&config.output_dir)
        .context("Failed to create output directory")?;

    let path = config.output_dir.join("huginn-collection.json");
    let json = serde_json::to_string_pretty(&system_info)?;
    std::fs::write(&path, json).context("Failed to write collection file")?;
    config.success(&format!("Collection saved: {}", path.display()));

    Ok(())
}

pub fn run_analyze(input: &Path, config: &RunnerConfig) -> anyhow::Result<()> {
    config.info(&format!("Loading collection from {}", input.display()));

    let content =
        std::fs::read_to_string(input).context("Failed to read collection file")?;
    let system_info: SystemInfo =
        serde_json::from_str(&content).context("Failed to parse collection file")?;

    config.section("Running security analyzers...");

    let analyzers = build_analyzer_registry();
    let mut findings = analyzers.run_all(&system_info, &|msg| config.info(msg));

    if !config.include_passed {
        findings.retain(|f| !f.passed);
    }

    let report = Report::new(system_info, findings);

    config.section("Writing outputs...");
    write_outputs(&report, config)?;

    Ok(())
}

pub fn run_report(input: &Path, config: &RunnerConfig) -> anyhow::Result<()> {
    config.info(&format!("Loading report from {}", input.display()));

    let content = std::fs::read_to_string(input).context("Failed to read report file")?;
    let report: Report = serde_json::from_str(&content).context("Failed to parse report file")?;

    config.section("Writing outputs...");
    write_outputs(&report, config)?;

    Ok(())
}

fn write_outputs(report: &Report, config: &RunnerConfig) -> anyhow::Result<()> {
    std::fs::create_dir_all(&config.output_dir)
        .context("Failed to create output directory")?;

    let fmt = &config.output_format;

    if matches!(fmt, OutputFormat::Json | OutputFormat::All) {
        let path = config.output_dir.join("huginn-report.json");
        let json = output::json::serialize(report)?;
        std::fs::write(&path, json).context("Failed to write JSON report")?;
        config.success(&format!("JSON:        {}", path.display()));
    }

    if matches!(fmt, OutputFormat::Bloodhound | OutputFormat::All) {
        let path = config.output_dir.join("huginn-bloodhound.json");
        let bh = output::bloodhound::build_bloodhound_output(report);
        let json = serde_json::to_string_pretty(&bh)?;
        std::fs::write(&path, json).context("Failed to write BloodHound output")?;
        config.success(&format!("BloodHound:  {}", path.display()));
    }

    if matches!(fmt, OutputFormat::Html | OutputFormat::All) {
        let path = config.output_dir.join("huginn-report.html");
        let html = output::html::render(report)?;
        std::fs::write(&path, html).context("Failed to write HTML report")?;
        config.success(&format!("HTML:        {}", path.display()));
    }

    Ok(())
}

fn build_collector_registry() -> CollectorRegistry {
    CollectorRegistry::new()
        .register(crate::collectors::system_info::SystemInfoCollector)
        .register(crate::collectors::users::UsersCollector)
        .register(crate::collectors::services::ServicesCollector)
        .register(crate::collectors::network::NetworkCollector)
        .register(crate::collectors::security_policies::SecurityPoliciesCollector)
        .register(crate::collectors::software::SoftwareCollector)
        .register(crate::collectors::scheduled_tasks::ScheduledTasksCollector)
}

fn build_analyzer_registry() -> AnalyzerRegistry {
    AnalyzerRegistry::new()
        .register(crate::analyzers::cis::account_policies::PasswordPolicyAnalyzer)
        .register(crate::analyzers::cis::account_policies::LockoutPolicyAnalyzer)
        .register(crate::analyzers::cis::security_options::UacAnalyzer)
        .register(crate::analyzers::cis::security_options::LsaProtectionAnalyzer)
        .register(crate::analyzers::cis::services::UnquotedServicePathAnalyzer)
        .register(crate::analyzers::cis::services::WeakServicePermissionsAnalyzer)
        .register(crate::analyzers::cis::network::FirewallAnalyzer)
        .register(crate::analyzers::cis::network::SmbV1Analyzer)
}
