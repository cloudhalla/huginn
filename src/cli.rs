use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "huginn",
    about = "Blue team security posture assessment",
    long_about = "Huginn collects system configuration data and evaluates it against \
                  CIS Benchmarks and NIST controls to identify security misconfigurations.",
    version,
    author
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Output format(s) to generate
    #[arg(short, long, default_value = "all", global = true)]
    pub output: OutputFormat,

    /// Output directory for generated files
    #[arg(short, long, default_value = "./huginn-output", global = true)]
    pub dir: PathBuf,

    /// Suppress progress output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Comma-separated list of collectors to run (default: all)
    #[arg(long, value_delimiter = ',', global = true)]
    pub collectors: Option<Vec<String>>,

    /// Include passed checks in output
    #[arg(long, global = true)]
    pub include_passed: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Collect, analyze, and report [default]
    Run,
    /// Collect raw system data only
    Collect,
    /// Analyze previously collected data file
    Analyze {
        /// Path to the system info JSON file from 'huginn collect'
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Generate report from a collected + analyzed JSON file
    Report {
        /// Path to the report JSON file from 'huginn analyze'
        #[arg(short, long)]
        input: PathBuf,
    },
}

#[derive(ValueEnum, Debug, Clone)]
pub enum OutputFormat {
    Json,
    Html,
    Bloodhound,
    All,
}
