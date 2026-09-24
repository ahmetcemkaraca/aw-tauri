// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clap::Parser;

/// PeakActivity desktop
#[derive(Parser, Debug)]
#[command(name = "peakactivity", version, about)]
struct Cli {
    /// Run in testing mode (port 5666, separate database)
    #[arg(long)]
    testing: bool,

    /// Enable verbose/debug logging
    #[arg(short, long)]
    verbose: bool,

    /// Override the port number
    #[arg(long)]
    port: Option<u16>,

    /// Run without GUI — no tray icon or windows, suitable for headless servers
    #[arg(long)]
    daemon: bool,

    /// Deprecated alias for the native desktop; use --daemon for a headless local API
    #[arg(long, conflicts_with = "daemon")]
    mini: bool,
}

fn main() {
    let cli = Cli::parse();
    aw_tauri_lib::set_cli_args(aw_tauri_lib::CliArgs {
        testing: cli.testing,
        verbose: cli.verbose,
        port: cli.port,
        daemon: cli.daemon,
        mini: cli.mini,
    });
    aw_tauri_lib::run();
}
