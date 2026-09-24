use aw_server::{
    config::AWConfig,
    endpoints::{build_rocket, ServerState},
};
use lazy_static::lazy_static;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs::{create_dir_all, read_to_string, remove_file, write, OpenOptions};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_opener::OpenerExt;

mod dirs;
mod ai_credentials;
mod entitlement;
mod logging;
mod manager;
mod mini;
mod vault;
mod sync;
mod vault_files;
mod local_session;
mod capture;

/// CLI arguments passed from main()
#[derive(Debug, Default)]
pub struct CliArgs {
    pub testing: bool,
    pub verbose: bool,
    pub port: Option<u16>,
    pub daemon: bool,
    pub mini: bool,
}

static CLI_ARGS: OnceLock<CliArgs> = OnceLock::new();
static DAEMON_MODE: OnceLock<bool> = OnceLock::new();
static MINI_MODE: OnceLock<bool> = OnceLock::new();

/// Returns true when running in headless daemon mode (no Tauri/GUI).
pub(crate) fn is_daemon_mode() -> bool {
    DAEMON_MODE.get().copied().unwrap_or(false)
}

/// Returns true when running in mini mode (tray + server, no Tauri WebView).
pub(crate) fn is_mini_mode() -> bool {
    MINI_MODE.get().copied().unwrap_or(false)
}

/// Set CLI args before calling run(). Must be called at most once.
pub fn set_cli_args(args: CliArgs) {
    CLI_ARGS.set(args).expect("CLI args already set");
}

fn get_cli_args() -> &'static CliArgs {
    CLI_ARGS.get_or_init(CliArgs::default)
}

use log::{error, info, trace, warn};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconId},
    webview::WebviewWindowBuilder,
    AppHandle, Manager, Url,
};

pub struct AppHandleWrapper(Mutex<AppHandle>);

impl Drop for AppHandleWrapper {
    fn drop(&mut self) {
        let (_lock, cvar) = &*HANDLE_CONDVAR;
        cvar.notify_all();
    }
}

static HANDLE: OnceLock<AppHandleWrapper> = OnceLock::new();
lazy_static! {
    static ref HANDLE_CONDVAR: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
}
#[derive(Debug)]
pub struct TrayIdWrapper(TrayIconId);

impl Drop for TrayIdWrapper {
    fn drop(&mut self) {
        let (_lock, cvar) = &*TRAY_CONDVAR;
        cvar.notify_all();
    }
}

static TRAY_ID: OnceLock<TrayIdWrapper> = OnceLock::new();
lazy_static! {
    static ref TRAY_CONDVAR: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
}
static CONFIG: OnceLock<UserConfig> = OnceLock::new();
static FIRST_RUN: OnceLock<bool> = OnceLock::new();

fn init_app_handle(handle: AppHandle) {
    HANDLE.get_or_init(|| AppHandleWrapper(Mutex::new(handle)));
    let (lock, _cvar) = &*HANDLE_CONDVAR;
    let mut started = lock.lock().expect("Failed to lock HANDLE_CONDVAR");
    *started = true;
}

pub(crate) fn get_app_handle() -> &'static Mutex<AppHandle> {
    &HANDLE.get().expect("HANDLE not initialized").0
}

fn init_tray_id(id: TrayIconId) {
    TRAY_ID
        .set(TrayIdWrapper(id))
        .expect("failed to set TRAY_ID");
    let (lock, _cvar) = &*TRAY_CONDVAR;
    let mut initialized = lock.lock().expect("Failed to lock TRAY_CONDVAR");
    *initialized = true;
}

pub(crate) fn get_tray_id() -> &'static TrayIconId {
    let (lock, cvar) = &*TRAY_CONDVAR;
    let mut initialized = lock.lock().expect("Failed to lock TRAY_CONDVAR");
    while !*initialized {
        initialized = cvar.wait(initialized).expect("Failed to wait for TRAY_ID");
    }
    &TRAY_ID.get().expect("TRAY_ID not initialized").0
}

// Escapes a value for use inside a double-quoted TOML basic string.
fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn write_formatted_config(config: &UserConfig, path: &Path) -> Result<(), std::io::Error> {
    // Helper function to write the config prettier
    let mut output = String::new();

    output.push_str(&format!("port = {}\n", config.port));

    output.push_str("discovery_paths = [");
    if !config.discovery_paths.is_empty() {
        output.push('\n');
        for path in &config.discovery_paths {
            output.push_str(&format!(
                "  \"{}\",\n",
                toml_escape(path.to_str().unwrap_or_default())
            ));
        }
        output.push(']');
    } else {
        output.push_str("]\n");
    }
    output.push_str("\n\n");

    // Add autostart section
    output.push_str("[autostart]\n");
    output.push_str(&format!("enabled = {}\n", config.autostart.enabled));
    output.push_str(&format!("minimized = {}\n", config.autostart.minimized));

    // Format modules with one per line
    output.push_str("modules = [\n");
    for module in &config.autostart.modules {
        match module {
            ModuleEntry::Simple(name) => {
                output.push_str(&format!("  \"{}\",\n", toml_escape(name)));
            }
            ModuleEntry::Full { name, args } => {
                output.push_str(&format!(
                    "  {{ name = \"{}\", args = \"{}\" }},\n",
                    toml_escape(name),
                    toml_escape(args)
                ));
            }
        }
    }

    if !config.autostart.modules.is_empty() {
        output.truncate(output.len() - 2); // Remove last comma and newline
        output.push('\n'); // Add back just the newline
    }
    output.push_str("]\n");

    // Add module_args section, for modules that aren't autostarted but still need args
    // when launched manually (e.g. from the tray menu) or restarted after a crash
    if !config.module_args.is_empty() {
        output.push_str("\n[module_args]\n");
        for (name, args) in &config.module_args {
            output.push_str(&format!(
                "\"{}\" = \"{}\"\n",
                toml_escape(name),
                toml_escape(args)
            ));
        }
    }

    write(path, output)
}

pub fn is_port_available(port: u16) -> std::io::Result<bool> {
    let addr = format!("127.0.0.1:{}", port)
        .parse::<SocketAddr>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    match TcpListener::bind(addr) {
        Ok(_) => Ok(true), // Port is available
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                Ok(false) // Port is in use
            } else {
                Err(e) // Other error occurred
            }
        }
    }
}

pub(crate) fn is_first_run() -> &'static bool {
    FIRST_RUN.get().expect("FIRST_RUN not initialized")
}

pub fn handle_first_run() {
    let first_run = is_first_run();
    if *first_run {
        thread::spawn(|| {
            let app = &*get_app_handle().lock().expect("Failed to get app handle");
            app.notification()
                .builder()
                .title("PeakActivity")
                .body("Welcome to PeakActivity! Click on the tray icon to launch the dashboard")
                .show()
                .expect("Failed to show first run notification");
            if let Some(window) = app.webview_windows().get("main") {
                window.show().expect("Failed to show main window");
            }
        });
    }
}

fn build_dashboard_url(port: u16) -> Url {
    Url::parse(&format!("http://127.0.0.1:{port}/")).expect("Invalid loopback URL")
}

pub fn listen_for_lockfile() {
    thread::spawn(|| {
        let runtime_path = get_runtime_path();
        loop {
            let watcher = match SpecificFileWatcher::new(&runtime_path, "single_instance.lock") {
                Ok(w) => w,
                Err(e) => {
                    warn!("Failed to create file watcher: {}. Retrying in 2s...", e);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };

            loop {
                match watcher.wait_for_file() {
                    Ok(()) => {
                        log::info!("Lock file detected");
                        remove_file(get_runtime_path().join("single_instance.lock"))
                            .expect("Failed to remove lock file");
                        let app = &*get_app_handle().lock().expect("Failed to get app handle");
                        if let Some(window) = app.webview_windows().get("main") {
                            window.show().expect("Failed to show main window");
                            window.set_focus().expect("Failed to focus main window");
                        }
                    }
                    Err(e) => {
                        warn!("File watcher exited: {}. Relaunching in 1s...", e);
                        thread::sleep(Duration::from_secs(1));
                        break;
                    }
                }
            }
        }
    });
}

pub struct SpecificFileWatcher {
    #[allow(dead_code)]
    watcher: RecommendedWatcher,
    rx: mpsc::Receiver<Result<Event, notify::Error>>,
    target_file: PathBuf,
}

impl SpecificFileWatcher {
    pub fn new<P: AsRef<Path>>(dir_path: P, filename: &str) -> Result<Self, notify::Error> {
        let (tx, rx) = mpsc::channel();

        let target_file = dir_path.as_ref().join(filename);

        // Configure the watcher with minimal overhead
        let config = Config::default().with_poll_interval(Duration::from_secs(1));

        // Create a watcher
        let mut watcher = RecommendedWatcher::new(tx, config)?;

        watcher.watch(dir_path.as_ref(), RecursiveMode::NonRecursive)?;

        Ok(Self {
            watcher,
            rx,
            target_file,
        })
    }

    pub fn wait_for_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        for result in self.rx.iter() {
            match result {
                Ok(event) => match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_)
                        if event.paths.iter().any(|p| p == &self.target_file) =>
                    {
                        return Ok(());
                    }
                    _ => {}
                },
                Err(e) => warn!("Watch error: {}", e),
            }
        }
        Err("Watcher channel closed".into())
    }
}

// Module representation that can be either a string or an object with name/args
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ModuleEntry {
    Simple(String),
    Full {
        name: String,
        #[serde(default = "String::new")]
        args: String,
    },
}

impl ModuleEntry {
    pub fn name(&self) -> &str {
        match self {
            ModuleEntry::Simple(name) => name,
            ModuleEntry::Full { name, .. } => name,
        }
    }

    pub fn args(&self) -> &str {
        match self {
            ModuleEntry::Simple(_) => "",
            ModuleEntry::Full { args, .. } => args,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutostartConfig {
    pub enabled: bool,
    pub minimized: bool,
    pub modules: Vec<ModuleEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserConfig {
    pub port: u16,
    pub discovery_paths: Vec<PathBuf>,
    pub autostart: AutostartConfig,
    /// Default args by module name, applied even if the module isn't autostarted.
    #[serde(default)]
    pub module_args: BTreeMap<String, String>,
}

impl Default for UserConfig {
    fn default() -> Self {
        let discovery_paths = dirs::get_discovery_paths();

        // Build default modules list based on platform and display server
        let mut modules = Vec::new();

        if cfg!(target_os = "linux") {
            // Check for Wayland using multiple environment variables
            let is_wayland = env::var("XDG_SESSION_TYPE")
                .map(|s| s == "wayland")
                .unwrap_or(false)
                || env::var("WAYLAND_DISPLAY").is_ok();

            if is_wayland {
                // On Linux with Wayland, use aw-awatcher instead of separate watchers
                modules.push(ModuleEntry::Simple("aw-awatcher".to_string()));
            } else {
                // On Linux with X11 or other display servers, use traditional watchers
                modules.push(ModuleEntry::Simple("aw-watcher-afk".to_string()));
                modules.push(ModuleEntry::Simple("aw-watcher-window".to_string()));
            }
        } else {
            // On non-Linux platforms, use traditional watchers
            modules.push(ModuleEntry::Simple("aw-watcher-afk".to_string()));
            modules.push(ModuleEntry::Simple("aw-watcher-window".to_string()));
        }

        UserConfig {
            port: 5601,
            discovery_paths,
            autostart: AutostartConfig {
                enabled: true,
                minimized: true,
                modules,
            },
            module_args: BTreeMap::new(),
        }
    }
}

fn get_config_path() -> PathBuf {
    dirs::get_config_path()
}

fn get_runtime_path() -> PathBuf {
    dirs::get_runtime_dir()
}

pub(crate) fn get_config() -> &'static UserConfig {
    CONFIG.get_or_init(|| {
        let config_path = get_config_path();
        if config_path.exists() {
            FIRST_RUN.set(false).expect("Failed to set FIRST_RUN");
            let config_str = read_to_string(&config_path).expect("Failed to read config file");

            // Try to parse the config file
            match toml::from_str::<UserConfig>(&config_str) {
                Ok(config) => config,
                Err(e) => {
                    warn!("Failed to parse config file: {}. Using default config.", e);

                    if !is_daemon_mode() && !is_mini_mode() {
                        let app = &*get_app_handle().lock().expect("Failed to get app handle");
                        app.dialog()
                            .message("Malformed config file. Using default config.")
                            .kind(MessageDialogKind::Error)
                            .title("Error")
                            .show(|_| {});
                    }

                    UserConfig::default()
                }
            }
        } else {
            FIRST_RUN.set(true).expect("failed to set FIRST_RUN");

            let config = UserConfig::default();
            create_dir_all(config_path.parent().unwrap()).expect("Failed to create config dir");
            write_formatted_config(&config, &config_path).expect("Failed to write config file");
            config
        }
    })
}

/// Run without a GUI: start the server and module manager, block until a signal
/// is received, then cleanly stop all modules.
fn run_daemon() {
    let cli_args = get_cli_args();
    let (_, server_state, aw_config) = prepare_aw_server(get_config(), cli_args)
        .unwrap_or_else(|error| {
            eprintln!("PeakActivity could not open its local vault: {error}");
            std::process::exit(1);
        });
    let port = aw_config.port;

    // Build Tokio runtime first so we can spawn Rocket before starting modules
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    // Spawn Rocket first so it begins binding the port before watchers start
    // connecting — matches the GUI path ordering (spawn then start_manager)
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let rocket_handle = rt.spawn(aw_server::endpoints::launch_with_readiness(server_state, aw_config, ready_tx));
    if !matches!(ready_rx.recv_timeout(Duration::from_secs(15)), Ok(Ok(()))) {
        eprintln!("PeakActivity could not bind its local API port");
        std::process::exit(1);
    }
    if let Err(error) = vault::unlock() {
        eprintln!("The local vault requires the native recovery interface: {error}");
        std::process::exit(1);
    }

    // Start module manager after Rocket is already starting up.
    // Pass the CLI-computed port so --testing and --port are respected.
    let manager_state = manager::start_manager_with_port(port);

    // Wait for server shutdown (Rocket handles SIGINT/SIGTERM cleanly)
    // Use match instead of expect so that stop_modules() always runs —
    // even if the Rocket task panics, we clean up watcher child processes.
    // Track whether the exit was abnormal so we can propagate a non-zero
    // exit code after cleanup — required for systemd/Docker restart policies.
    let exit_error = match rt.block_on(rocket_handle) {
        Ok(Err(e)) => {
            error!("Server exited with error: {:?}", e);
            true
        }
        Err(join_err) => {
            error!("Rocket task panicked: {:?}", join_err);
            true
        }
        Ok(Ok(_)) => {
            info!("Server shutdown cleanly");
            false
        }
    };

    info!("Server stopped, shutting down modules");
    capture::stop();
    manager_state
        .lock()
        .expect("Failed to lock manager state")
        .stop_modules();

    if exit_error {
        std::process::exit(1);
    }
}

/// Prepare the aw-server state, config, and dashboard URL.
/// Shared by mini mode and the Tauri GUI mode.
pub(crate) fn prepare_aw_server(
    user_config: &UserConfig,
    cli_args: &CliArgs,
) -> Result<(Url, ServerState, AWConfig), String> {
    let testing = cli_args.testing;

    let mut aw_config = AWConfig::default();
    aw_config.testing = testing;
    aw_config.address = "127.0.0.1".into();

    // Port priority: CLI flag > testing default (5666) > config file
    let mut port = cli_args.port.unwrap_or(if testing { 5667 } else { user_config.port });
    if port == 0 { return Err("Choose a nonzero local server port".into()); }
    if cli_args.port.is_none() && !is_port_available(port).map_err(|_| "Cannot inspect the local port")? {
        port = TcpListener::bind(("127.0.0.1", 0)).and_then(|listener| listener.local_addr())
            .map_err(|_| "No local server port is available")?.port();
    }
    aw_config.port = port;

    // Check port availability before opening the datastore — opening the SQLite
    // store acquires a lock, so bail on a busy port first (matches run_daemon's order).
    if !is_port_available(port).map_err(|e| format!("Failed to check port availability: {e}"))? {
        return Err(format!("Port {} is already in use", port));
    }

    let datastore = vault::initialize(testing)?;
    let device_id = vault::device_id(testing)?;
    aw_config.auth.sessions = Some(local_session::initialize(port, testing)?);

    let webui_var = if cfg!(debug_assertions) { std::env::var("AW_WEBUI_DIR") } else { Err(std::env::VarError::NotPresent) };

    let asset_path_opt = if let Ok(path_str) = &webui_var {
        let asset_path = PathBuf::from(path_str);
        if asset_path.exists() {
            info!("Using webui path: {}", path_str);
            Some(asset_path)
        } else {
            return Err("Path set via env var AW_WEBUI_DIR does not exist".to_string());
        }
    } else {
        info!("Using bundled assets");
        None
    };

    let server_state = ServerState {
        datastore,
        asset_resolver: aw_server::endpoints::AssetResolver::new(asset_path_opt),
        device_id,
    };
    if testing {
        info!("Running in testing mode (port {})", port);
    }
    let dashboard_url = build_dashboard_url(port);
    Ok((dashboard_url, server_state, aw_config))
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
fn open_external(url: String, app: tauri::AppHandle) {
    let Ok(target) = Url::parse(&url) else { return; };
    if !matches!(target.scheme(), "http" | "https") { return; }
    info!("Opening an external link");
    if app.opener().open_url(&url, None::<&str>).is_err() {
        warn!("Unable to open external link");
    }
}

#[cfg(target_os = "windows")]
fn permission_settings_url(source: &str) -> Option<&'static str> {
    matches!(source, "window" | "idle" | "browser").then_some("ms-settings:privacy")
}

#[cfg(target_os = "macos")]
fn permission_settings_url(source: &str) -> Option<&'static str> {
    matches!(source, "window" | "idle" | "browser")
        .then_some("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn permission_settings_url(_source: &str) -> Option<&'static str> { None }

#[tauri::command]
fn open_permission_settings(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
    source: String,
) -> Result<bool, String> {
    local_session::verify_window(&window)?;
    if !matches!(source.as_str(), "window" | "idle" | "browser") {
        return Err("Unsupported data source".into());
    }
    let Some(url) = permission_settings_url(&source) else { return Ok(false); };
    app.opener().open_url(url, None::<&str>).map_err(|_| "System settings could not be opened")?;
    Ok(true)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let context = tauri::generate_context!();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Ok(resource_dir) = tauri::utils::platform::resource_dir(
        context.package_info(),
        &tauri::Env::default(),
    ) {
        dirs::set_resource_dir(resource_dir);
    }
    // Rotate log if needed (before initializing logging)
    if let Err(e) = logging::rotate_log_if_needed() {
        eprintln!("Failed to rotate log: {}", e);
    }

    let cli_args = get_cli_args();

    // Set verbose env var before logging init so it picks it up
    if cli_args.verbose {
        std::env::set_var("AW_DEBUG", "1");
    }

    // Initialize logging
    if let Err(e) = logging::setup_logging() {
        // Can't use log here since logging isn't initialized yet
        eprintln!("Failed to initialize logging: {}", e);
    }

    if cli_args.daemon {
        DAEMON_MODE.set(true).expect("DAEMON_MODE already set");
        run_daemon();
        return;
    }

    if cli_args.mini {
        warn!("The browser-only mini mode has been retired; using the trusted native vault interface");
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::AppleScript,
            Some(vec![]),
        ))
        .plugin(tauri_plugin_single_instance::init(|_app, _args, _cwd| {
            let lock_path = get_runtime_path().join("single_instance.lock");
            if !lock_path.parent().unwrap().exists() {
                create_dir_all(lock_path.parent().unwrap()).expect("Failed to create runtime dir");
            }
            let _lock_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(lock_path)
                .expect("Failed to open lock file");
            info!("Another instance is running, quitting!");
        }))
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            {
                //TODO: Some of this setup could run concurrently. Could slash a few 100ms in startup?
                init_app_handle(app.handle().clone());
                let user_config = get_config();
                // Get the autostart manager
                let autostart_manager = app.autolaunch();

                match user_config.autostart.enabled {
                    true => {
                        if !autostart_manager
                            .is_enabled()
                            .expect("Failed to get autostart state")
                        {
                            autostart_manager
                                .enable()
                                .expect("Unable to enable autostart");
                            info!("Registered for autostart: true");
                        }
                    }
                    false => {
                        //checks for state before disabling no need to check twice
                        autostart_manager
                            .disable()
                            .expect("Unable to disable autosart");
                        info!("Registered for autostart: false");
                    }
                }

                let (dashboard_url, server_state, aw_config) = match prepare_aw_server(user_config, cli_args) {
                    Ok(prepared) => prepared,
                    Err(message) => {
                        let handle = app.handle().clone();
                        app.dialog().message(message).title("PeakActivity could not start")
                            .kind(MessageDialogKind::Error).show(move |_| handle.exit(1));
                        return Ok(());
                    }
                };
                let port = aw_config.port;
                let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
                tauri::async_runtime::spawn(aw_server::endpoints::launch_with_readiness(server_state, aw_config, ready_tx));
                if !matches!(ready_rx.recv_timeout(Duration::from_secs(15)), Ok(Ok(()))) {
                    let handle = app.handle().clone();
                    app.dialog().message("The local server could not start. Close the conflicting application or choose another --port.")
                        .title("Local server unavailable").kind(MessageDialogKind::Error).show(move |_| handle.exit(1));
                    return Ok(());
                }
                let trusted_origin = dashboard_url.origin();
                // Create main window programmatically to attach initialization script.
                // The script intercepts clicks on external links and opens them in the system
                // browser via the open_external Tauri command. This approach works reliably for
                // SPA-generated links where on_navigation (which only fires for top-level
                // webview navigations) would miss JS-driven internal route changes.
                let _main_window = WebviewWindowBuilder::new(
                    app,
                    "main",
                    tauri::WebviewUrl::External(dashboard_url),
                )
                .title("PeakActivity")
                .on_navigation(move |url| url.origin() == trusted_origin)
                .inner_size(800.0, 600.0)
                .visible(false)
                .initialization_script(
                    r#"
                    document.addEventListener('click', function(e) {
                        var el = e.target;
                        while (el && el.tagName !== 'A') { el = el.parentElement; }
                        if (el && el.href && new URL(el.href).origin !== window.location.origin) {
                            e.preventDefault();
                            e.stopPropagation();
                            window.__TAURI_INTERNALS__.invoke('open_external', { url: el.href });
                        }
                    }, true);
                    "#,
                )
                .build()
                .expect("Failed to create main window");
                let manager_state = manager::start_manager_with_port(port);

                let open = MenuItem::with_id(app, "open", "Open Dashboard", true, None::<&str>)
                    .expect("Failed to create open menu item");
                let quit = MenuItem::with_id(app, "quit", "Quit PeakActivity", true, None::<&str>)
                    .expect("Failed to create quit menu item");

                let menu =
                    Menu::with_items(app, &[&open, &quit]).expect("Failed to create tray menu");

                #[cfg(not(target_os = "windows"))]
                let tray_builder = TrayIconBuilder::new()
                    .icon(
                        app.default_window_icon()
                            .expect("Failed to get window icon")
                            .clone(),
                    )
                    .menu(&menu)
                    .show_menu_on_left_click(true);

                #[cfg(target_os = "windows")]
                let tray_builder = TrayIconBuilder::new()
                    .icon(
                        app.default_window_icon()
                            .expect("Failed to get window icon")
                            .clone(),
                    )
                    .menu(&menu)
                    .show_menu_on_left_click(true)
                    .tooltip("PeakActivity");
                let tray = tray_builder.build(app).expect("Failed to create tray");

                init_tray_id(tray.id().clone());
                app.on_menu_event(move |app, event| {
                    if event.id().0 == "open" {
                        trace!("system tray received a open click");
                        let windows = app.webview_windows();
                        let window = windows.get("main").expect("Main window not found");
                        window.show().expect("Failed to show window");
                        window.set_focus().expect("Failed to focus window");
                    } else if event.id().0 == "quit" {
                        trace!("quit clicked!");
                        let mut state = manager_state
                            .lock()
                            .expect("Failed to acquire manager_state lock");
                        drop(state);
                        if let Err(error) = vault::lock() {
                            warn!("Local vault did not confirm shutdown: {error}");
                            return;
                        }
                        let mut state = manager_state.lock().expect("Failed to acquire manager_state lock");
                        state.stop_modules();
                        app.exit(0);
                    } else if event.id().0.starts_with("capture_") {
                        let result = match event.id().0.as_str() {
                            "capture_pause" => capture::pause().map(|_| ()),
                            "capture_pause_15" => capture::pause_for(chrono::Duration::minutes(15)).map(|_| ()),
                            "capture_pause_60" => capture::pause_for(chrono::Duration::hours(1)).map(|_| ()),
                            "capture_pause_tomorrow" => capture::pause_until_tomorrow().map(|_| ()),
                            "capture_private" => capture::enter_private_mode().map(|_| ()),
                            "capture_resume" => capture::resume().map(|_| ()),
                            _ => Err("Unknown recording control".into()),
                        };
                        if let Err(message) = result {
                            warn!("Tray recording control failed: {message}");
                            let _ = app.notification().builder().title("Recording controls").body(message).show();
                        }
                    } else if event.id().0 == "config_folder" {
                        let config_path = get_config_path();
                        let config_dir = config_path.parent().unwrap_or(&config_path);
                        app.opener()
                            .reveal_item_in_dir(config_dir)
                            .expect("Failed to open config folder");
                    } else if event.id().0 == "log_folder" {
                        let log_path = logging::get_log_path();
                        let log_dir = log_path.parent().unwrap_or(&log_path);
                        app.opener()
                            .reveal_item_in_dir(log_dir)
                            .expect("Failed to open log folder");
                    } else {
                        // Modules menu clicks
                        let mut state = manager_state
                            .lock()
                            .expect("Failed to acquire manager_state lock");
                        state.handle_system_click(&event.id().0);
                    }
                });
                if !user_config.autostart.minimized || *is_first_run() || !vault::status().has_vault {
                    if let Some(window) = app.webview_windows().get("main") {
                        window.show().expect("Failed to show main window");
                    }
                }
            }

            if vault::status().has_vault {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn_blocking(move || {
                    if vault::unlock().is_err() {
                        if let Some(window) = handle.get_webview_window("main") { let _ = window.show(); }
                    }
                });
            }
            handle_first_run();
            listen_for_lockfile();
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = &event {
                api.prevent_close();
                window.hide().expect("Failed to hide main window");
            };
        })
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![greet, open_external, open_permission_settings, local_session::local_session,
            ai_credentials::save_ai_credential, ai_credentials::delete_ai_credential,
            ai_credentials::has_ai_credential, ai_credentials::send_ai_request,
            local_session::pause_capture, local_session::pause_capture_for, local_session::pause_capture_until_tomorrow,
            local_session::enter_private_mode, local_session::resume_capture, local_session::capture_runtime,
            entitlement::install_signed_entitlement, entitlement::load_entitlement_status,
            vault::vault_status, vault::unlock_vault, vault::lock_vault, vault::backup_vault,
            vault::restore_vault, vault::rotate_vault_key, vault::rollback_vault, vault::delete_local_vault,
            vault::support_bundle_preview, vault::export_support_bundle, vault::repair_privacy,
            sync::list_sync_devices, sync::create_local_sync_identity, sync::create_sync_pairing, sync::respond_sync_pairing,
            sync::complete_sync_pairing, sync::prepare_sync_pairing, sync::confirm_sync_pairing,
            sync::create_sync_key_transfer, sync::accept_sync_key_transfer,
            sync::list_sync_device_access_history, sync::list_sync_tombstone_statuses,
            sync::revoke_sync_device,
            sync::rotate_sync_keys,
            sync::create_current_sync_snapshot,
            sync::create_sync_recovery_kit, sync::verify_sync_recovery_kit,
            sync::export_sync_snapshot,
            sync::preview_sync_recovery_restore, sync::restore_sync_recovery_kit,
            sync::confirm_sync_recovery_saved,
            sync::sync_recovery_confirmed, sync::cancel_sync_recovery_kit,
            sync::cancel_sync_pairing])
        .run(context)
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    #[test]
    fn dashboard_url_never_carries_credentials() {
        let url = super::build_dashboard_url(5600);
        assert_eq!(url.as_str(), "http://127.0.0.1:5600/");
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
    }

    #[test]
    fn permission_settings_target_is_fixed_or_manual() {
        #[cfg(target_os = "windows")]
        assert_eq!(super::permission_settings_url("window"), Some("ms-settings:privacy"));
        #[cfg(target_os = "macos")]
        assert_eq!(super::permission_settings_url("window"), Some("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"));
        #[cfg(target_os = "linux")]
        assert_eq!(super::permission_settings_url("window"), None);
        assert_eq!(super::permission_settings_url("unknown"), None);
    }
}

#[cfg(test)]
mod shipping_tests {
    use super::UserConfig;

    #[test]
    fn default_modules_are_capture_helpers_only() {
        let config = UserConfig::default();
        assert!(!config.autostart.modules.is_empty());
        assert!(config.autostart.modules.iter().all(|module|
            matches!(module.name(), "aw-watcher-afk" | "aw-watcher-window" | "aw-awatcher")));
    }
}
