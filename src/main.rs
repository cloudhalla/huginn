mod analyzers;
mod cli;
mod collectors;
mod error;
mod models;
mod output;
mod platform;
mod runner;

use clap::Parser;
use cli::{Cli, Command};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = runner::RunnerConfig {
        output_dir: cli.dir,
        output_format: cli.output,
        quiet: cli.quiet,
        collectors: cli.collectors,
        include_passed: cli.include_passed,
    };

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => runner::run_full(&config)?,
        Command::Collect => runner::run_collect_only(&config)?,
        Command::Analyze { input } => runner::run_analyze(&input, &config)?,
        Command::Report { input } => runner::run_report(&input, &config)?,
    }

    Ok(())
}
