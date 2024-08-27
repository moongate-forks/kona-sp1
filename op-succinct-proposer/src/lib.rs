use anyhow::Result;
use std::sync::Arc;
use std::{process::Command, time::Duration};
use tokio::process::Child;
use tokio::sync::Mutex;

use kona_host::HostCli;
use log::error;

/// Convert the HostCli to a vector of arguments that can be passed to a command.
pub fn convert_host_cli_to_args(host_cli: &HostCli) -> Vec<String> {
    let mut args = vec![
        format!("--l1-head={}", host_cli.l1_head),
        format!("--l2-head={}", host_cli.l2_head),
        format!("--l2-output-root={}", host_cli.l2_output_root),
        format!("--l2-claim={}", host_cli.l2_claim),
        format!("--l2-block-number={}", host_cli.l2_block_number),
        format!("--l2-chain-id={}", host_cli.l2_chain_id),
    ];
    if let Some(addr) = &host_cli.l2_node_address {
        args.push("--l2-node-address".to_string());
        args.push(addr.to_string());
    }
    if let Some(addr) = &host_cli.l1_node_address {
        args.push("--l1-node-address".to_string());
        args.push(addr.to_string());
    }
    if let Some(addr) = &host_cli.l1_beacon_address {
        args.push("--l1-beacon-address".to_string());
        args.push(addr.to_string());
    }
    if let Some(dir) = &host_cli.data_dir {
        args.push("--data-dir".to_string());
        args.push(dir.to_string_lossy().into_owned());
    }
    if let Some(exec) = &host_cli.exec {
        args.push("--exec".to_string());
        args.push(exec.to_string());
    }
    if host_cli.server {
        args.push("--server".to_string());
    }
    args
}

/// Run the native host with a timeout. Use a binary to execute the native host, as opposed to
/// spawning a new thread in the same process due to the static cursors employed by the host.
pub async fn run_native_host(
    host_cli: &HostCli,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .exec()
        .expect("Failed to get cargo metadata");
    let target_dir = metadata.target_directory.join("release");
    let args = convert_host_cli_to_args(host_cli);

    // Run the native host runner.
    let child = tokio::process::Command::new(target_dir.join("native_host_runner"))
        .args(&args)
        .env("RUST_LOG", "info")
        .spawn()?;
    let child = Arc::new(Mutex::new(child));
    let child_clone = Arc::clone(&child);

    // Time out the native host runner after the given timeout.
    let result = tokio::select! {
        status = wait_for_child(child_clone) => status,
        _ = tokio::time::sleep(timeout) => {
            kill_child(&child).await;
            Err(anyhow::anyhow!("Native host runner process timed out after {} seconds", timeout.as_secs()))
        }
    };

    result
}

/// Wait for the child process to exit.
async fn wait_for_child(child: Arc<Mutex<Child>>) -> Result<std::process::ExitStatus> {
    let mut child = child.lock().await;
    child.wait().await.map_err(Into::into)
}

/// Kill the child process.
async fn kill_child(child: &Arc<Mutex<Child>>) {
    let mut child = child.lock().await;
    if let Err(e) = child.kill().await {
        error!("Failed to kill child process: {}", e);
    }
}
