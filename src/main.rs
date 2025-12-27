// SPDX-License-Identifier: AGPL-3.0-or-later

//! Seambot - Seam Hygiene Auditor
//!
//! Tracks, enforces, and detects drift in architectural boundaries (seams).
//!
//! Seambot is a governor and auditor, not a designer. It ensures that
//! declared seams remain explicit, stable, and correctly exercised over time.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

mod checks;
mod report;
mod seam;
mod register;

use report::{OutputFormat, Reporter};

/// Seam hygiene auditor for architectural boundaries
#[derive(Parser, Debug)]
#[command(name = "seambot")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the repository root
    #[arg(short, long, default_value = ".")]
    path: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check seam hygiene (all checks)
    Check {
        /// Fail on warnings
        #[arg(long)]
        strict: bool,

        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify seam register completeness
    Register {
        /// Path to seam register (defaults to spec/seams/seam-register.json)
        #[arg(long)]
        register: Option<PathBuf>,
    },

    /// Check for seam drift between declared and observed interfaces
    Drift {
        /// Compare against a baseline file
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Update baseline after check
        #[arg(long)]
        update_baseline: bool,
    },

    /// Validate conformance examples
    Conformance {
        /// Specific seam to check (checks all if omitted)
        #[arg(long)]
        seam: Option<String>,
    },

    /// Generate a seam status report
    Report {
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Include full details
        #[arg(long)]
        full: bool,
    },

    /// Initialize seam infrastructure in a repository
    Init {
        /// Force overwrite existing files
        #[arg(long)]
        force: bool,
    },

    /// Validate stage freeze has seam-freeze stamp
    FreezeCheck {
        /// Stage identifier (e.g., f1, f2)
        #[arg(long)]
        stage: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("seambot={}", log_level).into()),
        )
        .init();

    info!("Seambot v{}", env!("CARGO_PKG_VERSION"));

    let repo_path = cli.path.canonicalize()?;
    info!("Analyzing repository: {}", repo_path.display());

    match cli.command {
        Commands::Check { strict, output } => {
            let result = checks::run_all_checks(&repo_path).await?;
            let reporter = Reporter::new(cli.format);
            reporter.output(&result, output.as_deref())?;

            if result.has_errors() || (strict && result.has_warnings()) {
                std::process::exit(1);
            }
        }

        Commands::Register { register } => {
            let register_path = register.unwrap_or_else(|| {
                repo_path.join("spec/seams/seam-register.json")
            });
            let result = checks::check_register(&repo_path, &register_path).await?;
            let reporter = Reporter::new(cli.format);
            reporter.output(&result, None)?;

            if result.has_errors() {
                std::process::exit(1);
            }
        }

        Commands::Drift { baseline, update_baseline } => {
            let result = checks::check_drift(&repo_path, baseline.as_deref()).await?;
            let reporter = Reporter::new(cli.format);
            reporter.output(&result, None)?;

            if update_baseline {
                checks::update_drift_baseline(&repo_path).await?;
                info!("Updated drift baseline");
            }

            if result.has_errors() {
                std::process::exit(1);
            }
        }

        Commands::Conformance { seam } => {
            let result = checks::check_conformance(&repo_path, seam.as_deref()).await?;
            let reporter = Reporter::new(cli.format);
            reporter.output(&result, None)?;

            if result.has_errors() {
                std::process::exit(1);
            }
        }

        Commands::Report { output, full } => {
            let result = checks::generate_report(&repo_path, full).await?;
            let reporter = Reporter::new(cli.format);
            reporter.output(&result, output.as_deref())?;
        }

        Commands::Init { force } => {
            register::init_seam_infrastructure(&repo_path, force).await?;
            info!("Initialized seam infrastructure");
        }

        Commands::FreezeCheck { stage } => {
            let result = checks::check_freeze_stamp(&repo_path, &stage).await?;
            let reporter = Reporter::new(cli.format);
            reporter.output(&result, None)?;

            if result.has_errors() {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
