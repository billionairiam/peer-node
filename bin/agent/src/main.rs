#[macro_use]
extern crate lazy_static;

use anyhow::{Result, anyhow, bail};
use clap::Parser;
use nix::fcntl::OFlag;
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, VsockAddr};
use nix::unistd;
use slog::{Logger, debug, info, o, warn};
use std::fs::File;
use std::os::fd::{FromRawFd, RawFd};
use std::path::Path;
use std::process::Stdio;
use std::process::exit;
use std::sync::Arc;
use std::{env, vec};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio::sync::watch::Receiver;
use tokio::sync::watch::channel;
use tokio::task::JoinHandle;

use futures::future::join_all;

mod config;
mod initdata;
mod pipestream;
mod tracer;
mod util;
mod version;

use config::AgentConfig;
use pipestream::PipeStream;

use const_format::concatcp;
use tracing::{instrument, span};

use crate::config::GuestComponentsProcs;
use crate::initdata::{AA_CONFIG_PATH, CDH_CONFIG_PATH, InitdataReturnValue};

const NAME: &str = "node-agent";

const UNIX_SOCKET_PREFIX: &str = "unix://";

const AA_PATH: &str = "/usr/local/bin/attestation-agent";
const AA_ATTESTATION_SOCKET: &str =
    "/run/confidential-containers/attestation-agent/attestation-agent.sock";
const AA_ATTESTATION_URI: &str = concatcp!(UNIX_SOCKET_PREFIX, AA_ATTESTATION_SOCKET);

const CDH_PATH: &str = "/usr/local/bin/confidential-data-hub";
const CDH_SOCKET: &str = "/run/confidential-containers/cdh.sock";

const API_SERVER_PATH: &str = "/usr/local/bin/api-server-rest";

const DEFAULT_LAUNCH_PROCESS_TIMEOUT: i32 = 6;

lazy_static! {
    static ref AGENT_CONFIG: AgentConfig = AgentConfig::default();
}

#[derive(Parser)]
#[clap(disable_version_flag = true)]
struct AgentOpt {
    #[clap(short, long)]
    version: bool,
    /// Specify a custom agent config file
    #[clap(short, long)]
    config: Option<String>,
}

#[instrument]
fn announce(logger: &Logger, config: &AgentConfig) {
    info!(logger, "announce";
    "agent-commit" => version::VERSION_COMMIT,
    "agent-version" => version::AGENT_VERSION,
    "api-version" => version::API_VERSION,
    "config" => format!("{:?}", config),
    );
}

async fn create_logger_task(rfd: RawFd, vsock_port: u32, shutdown: Receiver<bool>) -> Result<()> {
    let mut reader = PipeStream::from_fd(rfd);
    let mut writer: Box<dyn AsyncWrite + Unpin + Send> = if vsock_port > 0 {
        let listenfd = socket::socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )?;

        let addr = VsockAddr::new(libc::VMADDR_CID_ANY, vsock_port);
        socket::bind(listenfd, &addr)?;
        socket::listen(listenfd, 1)?;

        Box::new(util::get_vsock_stream(listenfd).await?)
    } else {
        Box::new(tokio::io::stdout())
    };

    let _ = util::interruptable_io_copier(&mut reader, &mut writer, shutdown).await;

    Ok(())
}

async fn real_main() -> Result<()> {
    unsafe {
        env::set_var("RUST_BACKTRACE", "full");
    }

    let mut _children = vec![];

    let mut tasks: Vec<JoinHandle<Result<()>>> = vec![];

    let (rfd, wfd) = unistd::pipe2(OFlag::O_CLOEXEC)?;

    let (shutdown_tx, shutdown_rs) = channel(true);

    lazy_static::initialize(&AGENT_CONFIG);

    let config = &AGENT_CONFIG;
    let log_vport = config.log_vport as u32;
    let log_handle = tokio::spawn(create_logger_task(rfd, log_vport, shutdown_rs));

    tasks.push(log_handle);

    let writer_file = unsafe { File::from_raw_fd(wfd) };
    let tokio_writer = tokio::fs::File::from_std(writer_file);
    let log_writer = Arc::new(Mutex::new(tokio_writer));

    let (slog_rfd, slog_wfd) = unistd::pipe2(OFlag::O_CLOEXEC)?;
    let slog_file = unsafe { File::from_raw_fd(slog_wfd) };

    let move_log_writer = log_writer.clone();
    let main_log_forward_task = tokio::spawn(async move {
        let mut reader = PipeStream::from_fd(slog_rfd);
        forward_log_stream(&mut reader, move_log_writer).await
    });
    tasks.push(main_log_forward_task);

    let (logger, logger_async_guard) =
        logging::create_logger(NAME, "agent", config.log_level, slog_file);

    announce(&logger, config);

    let global_logger = slog_scope::set_global_logger(logger.new(o!("subsystem" => "agent")));
    global_logger.cancel_reset();

    let mut ttrpc_log_guard: Result<(), log::SetLoggerError> = Ok(());

    if config.log_level == slog::Level::Trace {
        ttrpc_log_guard = Ok(slog_stdlog::init()?)
    }

    if config.tracing {
        tracer::setup_tracing(NAME, &logger)?;
    }

    let root_span = span!(tracing::Level::TRACE, "root-span");

    let span_guard = root_span.enter();

    let initdata_return_value = initdata::initialize_initdata(&logger).await?;

    let gc_procs = config.guest_components_procs;
    if !attestation_binaries_available(&logger, &gc_procs) {
        bail!("attestation binaries requested for launch not available");
    } else {
        let (mut forwarder_tasks, children) = init_attestation_components(
            &logger,
            config,
            &initdata_return_value,
            log_writer.clone(),
        )
        .await?;

        _children = children;
        tasks.append(&mut forwarder_tasks);
    }

    let global_logger_guard2 =
        slog_scope::set_global_logger(slog::Logger::root(slog::Discard, o!()));
    global_logger_guard2.cancel_reset();

    let results = join_all(tasks).await;

    drop(logger_async_guard);

    drop(ttrpc_log_guard);

    shutdown_tx
        .send(true)
        .map_err(|e| anyhow!(e).context("failed to request shutdown"))?;

    drop(span_guard);
    drop(root_span);

    eprintln!("{} shutdown complete", NAME);

    let mut wait_errors: Vec<tokio::task::JoinError> = vec![];
    for result in results {
        if let Err(e) = result {
            eprintln!("wait task error: {:#?}", e);
            wait_errors.push(e);
        }
    }

    if wait_errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("wait all tasks failed: {:#?}", wait_errors).into())
    }
}

fn main() -> Result<(), anyhow::Error> {
    let args = AgentOpt::parse();

    if args.version {
        println!(
            "{} version {} (api version: {}, commit version: {}, type: rust",
            NAME,
            version::AGENT_VERSION,
            version::API_VERSION,
            version::VERSION_COMMIT,
        );
        exit(0);
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(real_main());

    result
}

async fn forward_log_stream<R, W>(reader: R, writer: Arc<Mutex<W>>) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let mut guard = writer.lock().await;
                if let Err(e) = guard.write_all(line.as_bytes()).await {
                    eprintln!("Failed to write to log pipe from {}", e);
                }
            }
            Err(e) => {
                eprintln!("Error reading from stream: {}", e);
                break;
            }
        }
    }
    Ok(())
}

async fn launch_process(
    logger: &Logger,
    path: &str,
    mut args: Vec<&str>,
    config: Option<&str>,
    socket_path: &str,
    timeout_secs: i32,
    envs: &[(&str, &str)],
) -> Result<Child> {
    if !Path::new(path).exists() {
        bail!("path {} does not exist.", path);
    }

    if let Some(config_path) = config {
        if Path::new(config_path).exists() {
            args.push("-c");
            args.push(config_path);
        }
    }

    if !socket_path.is_empty() && Path::new(socket_path).exists() {
        tokio::fs::remove_file(socket_path).await?;
    }

    let mut process = tokio::process::Command::new(path);

    process.kill_on_drop(true);

    process.args(args);
    for (k, v) in envs {
        process.env(k, v);
    }
    process.stdout(Stdio::piped()).stderr(Stdio::piped());

    let child = process.spawn()?;

    if !socket_path.is_empty() && timeout_secs > 0 {
        wait_for_path_to_exist(logger, socket_path, timeout_secs).await?;
    }

    Ok(child)
}

async fn wait_for_path_to_exist(logger: &Logger, path: &str, timeout_secs: i32) -> Result<()> {
    let p = Path::new(path);
    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if p.exists() {
            return Ok(());
        }
        if attempts >= timeout_secs {
            break;
        }
        attempts += 1;
        info!(
            logger,
            "waiting for {} to exist (attemp={})", path, attempts
        );
    }

    Err(anyhow!("wait for {} to exist timeout", path))
}

async fn launch_guest_component_procs<W>(
    logger: &Logger,
    config: &AgentConfig,
    initdata_return_value: &Option<InitdataReturnValue>,
    log_writer: Arc<Mutex<W>>,
) -> Result<(Vec<JoinHandle<Result<()>>>, Vec<Child>)>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut children = vec![];
    let mut forwarder_tasks = vec![];

    if config.guest_components_procs == GuestComponentsProcs::None {
        return Ok((forwarder_tasks, children));
    }

    debug!(logger, "spawning attestation-agent process {}", AA_PATH);
    let mut aa_args = vec!["--attestation_sock", AA_ATTESTATION_URI];
    if initdata_return_value.is_some() {
        aa_args.push("--initdata-toml");
        aa_args.push(initdata::INITDATA_TOML_PATH);
    }

    let mut aa_child = launch_process(
        logger,
        AA_PATH,
        aa_args,
        Some(AA_CONFIG_PATH),
        AA_ATTESTATION_SOCKET,
        DEFAULT_LAUNCH_PROCESS_TIMEOUT,
        &[],
    )
    .await
    .map_err(|e| anyhow!("launch_process {} failed: {:?}", AA_PATH, e))?;

    // Create forwarding tasks for AA's stdout and stderr
    let aa_stdout = aa_child.stdout.take().expect("Failed to capture AA stdout");
    let aa_stderr = aa_child.stderr.take().expect("Failed to capture AA stderr");
    forwarder_tasks.push(tokio::spawn(forward_log_stream(
        aa_stdout,
        log_writer.clone(),
    )));
    forwarder_tasks.push(tokio::spawn(forward_log_stream(
        aa_stderr,
        log_writer.clone(),
    )));

    children.push(aa_child);

    if config.guest_components_procs == GuestComponentsProcs::AttestationAgent {
        return Ok((forwarder_tasks, children));
    }

    debug!(
        logger,
        "spawning confidential-data-hub process {}", CDH_PATH
    );

    let mut cdh_child = launch_process(
        logger,
        CDH_PATH,
        vec![],
        Some(CDH_CONFIG_PATH),
        CDH_SOCKET,
        DEFAULT_LAUNCH_PROCESS_TIMEOUT,
        &[],
    )
    .await
    .map_err(|e| anyhow!("launch_process {} failed: {:?}", CDH_PATH, e))?;

    // Create forwarding tasks for CDH's stdout and stderr
    let cdh_stdout = cdh_child
        .stdout
        .take()
        .expect("Failed to capture CDH stdout");
    let cdh_stderr = cdh_child
        .stderr
        .take()
        .expect("Failed to capture CDH stderr");
    forwarder_tasks.push(tokio::spawn(forward_log_stream(
        cdh_stdout,
        log_writer.clone(),
    )));
    forwarder_tasks.push(tokio::spawn(forward_log_stream(
        cdh_stderr,
        log_writer.clone(),
    )));

    children.push(cdh_child);

    if config.guest_components_procs == GuestComponentsProcs::ConfidentialDataHub {
        return Ok((forwarder_tasks, children));
    }

    let features = config.guest_components_rest_api;
    debug!(
        logger,
        "spaning api server-rest process {} --features {}", API_SERVER_PATH, features
    );

    let mut api_child = launch_process(
        logger,
        API_SERVER_PATH,
        vec!["--features", &features.to_string()],
        None,
        "",
        0,
        &[],
    )
    .await
    .map_err(|e| anyhow!("launch_process {} failed: {:?}", API_SERVER_PATH, e))?;

    // Create forwarding tasks for API's stdout and stderr
    let api_stdout = api_child
        .stdout
        .take()
        .expect("Failed to capture API stdout");
    let api_stderr = api_child
        .stderr
        .take()
        .expect("Failed to capture API stderr");
    forwarder_tasks.push(tokio::spawn(forward_log_stream(
        api_stdout,
        log_writer.clone(),
    )));
    forwarder_tasks.push(tokio::spawn(forward_log_stream(
        api_stderr,
        log_writer.clone(),
    )));

    children.push(api_child);

    Ok((forwarder_tasks, children))
}

async fn init_attestation_components<W>(
    logger: &Logger,
    config: &AgentConfig,
    initdata_return_value: &Option<InitdataReturnValue>,
    log_writer: Arc<Mutex<W>>,
) -> Result<(Vec<JoinHandle<Result<()>>>, Vec<Child>)>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (forwarder_tasks, children) =
        launch_guest_component_procs(logger, config, initdata_return_value, log_writer).await?;

    Ok((forwarder_tasks, children))
}

fn attestation_binaries_available(logger: &Logger, procs: &GuestComponentsProcs) -> bool {
    let binaries = match procs {
        GuestComponentsProcs::AttestationAgent => vec![AA_PATH],
        GuestComponentsProcs::ConfidentialDataHub => vec![AA_PATH, CDH_PATH],
        GuestComponentsProcs::ApiServerRest => vec![AA_PATH, CDH_PATH, API_SERVER_PATH],
        _ => vec![],
    };
    for binary in binaries.iter() {
        if !Path::new(binary).exists() {
            warn!(logger, "{} not found", binary);
            return false;
        }
    }
    true
}
