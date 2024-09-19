use alloy_primitives::B256;
use anyhow::{bail, Result};
use op_succinct_client_utils::boot::hash_rollup_config;
use op_succinct_host_utils::fetcher::{OPSuccinctDataFetcher, RPCMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sp1_sdk::{HashableKey, ProverClient};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

pub const AGG_ELF: &[u8] = include_bytes!("../../../elf/aggregation-elf");

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The config for deploying the ZK L2OutputOracle.
/// Note: The fields should be in alphabetical order for Solidity to parse it correctly.
struct L2OOConfig {
    chain_id: u64,
    challenger: String,
    finalization_period: u64,
    l2_block_time: u64,
    l2_output_oracle_proxy: String,
    owner: String,
    proposer: String,
    rollup_config_hash: String,
    starting_block_number: u64,
    starting_output_root: String,
    starting_timestamp: u64,
    submission_interval: u64,
    verifier_gateway: String,
    vkey: String,
}

/// Update the L2OO config with the rollup config hash and other relevant data before the contract is deployed.
///
/// Specifically, updates the following fields in `zkl2ooconfig.json`:
/// - rollup_config_hash: Get the hash of the rollup config in rollup-configs/{l2_chain_id}.json.
/// - l2_block_time: Get the block time from the rollup config.
/// - starting_block_number: If `USE_CACHED_STARTING_BLOCK` is `false`, set starting_block_number to 10 blocks before the latest block on L2.
/// - starting_output_root: Set to the output root of the starting block number.
/// - starting_timestamp: Set to the timestamp of the starting block number.
/// - chain_id: Get the chain id from the rollup config.
/// - vkey: Get the vkey from the aggregation program ELF.
async fn update_l2oo_config() -> Result<()> {
    let data_fetcher = OPSuccinctDataFetcher::default();

    // Get the workspace root with cargo metadata to make the paths.
    let workspace_root =
        PathBuf::from(cargo_metadata::MetadataCommand::new().exec()?.workspace_root);

    // Read the L2OO config from the contracts directory.
    let mut l2oo_config = get_existing_l2oo_config(&workspace_root)?;

    // If we are not using a cached starting block number, set it to 10 blocks before the latest block on L2.
    if env::var("USE_CACHED_STARTING_BLOCK").unwrap_or("false".to_string()) != "true" {
        // Set the starting block number to 10 blocks before the latest block on L2.
        let latest_block = data_fetcher.get_head(RPCMode::L2).await?;
        l2oo_config.starting_block_number = latest_block.number - 20;
    }

    // Convert the starting block number to a hex string for the optimism_outputAtBlock RPC call.
    let starting_block_number_hex = format!("0x{:x}", l2oo_config.starting_block_number);
    let optimism_output_data: Value = data_fetcher
        .fetch_rpc_data(
            RPCMode::L2Node,
            "optimism_outputAtBlock",
            vec![starting_block_number_hex.into()],
        )
        .await?;

    // Hash the rollup config.
    let hash: B256 = hash_rollup_config(&data_fetcher.rollup_config);
    // Set the rollup config hash.
    let hash_str = format!("0x{:x}", hash);
    l2oo_config.rollup_config_hash = hash_str;

    // Set the L2 block time from the rollup config.
    l2oo_config.l2_block_time = data_fetcher.rollup_config.block_time;

    // Set the starting output root and starting timestamp.
    l2oo_config.starting_output_root =
        optimism_output_data["outputRoot"].as_str().unwrap().to_string();
    l2oo_config.starting_timestamp =
        optimism_output_data["blockRef"]["timestamp"].as_u64().unwrap();

    // Set the submission interval.
    l2oo_config.submission_interval =
        env::var("SUBMISSION_INTERVAL").unwrap_or("150".to_string()).parse()?;

    // Set the chain id.
    l2oo_config.chain_id = data_fetcher.get_chain_id(RPCMode::L2).await?;

    // Set the vkey.
    let prover = ProverClient::new();
    let (_, vkey) = prover.setup(AGG_ELF);
    l2oo_config.vkey = vkey.vk.bytes32();

    // Write the L2OO rollup config to the zkl2ooconfig.json file.
    write_l2oo_config(l2oo_config, &workspace_root)?;

    Ok(())
}

/// Get the L2OO rollup config from the contracts directory.
///
/// Note: The L2OO config is stored in `contracts/zkl2ooconfig.json`.
fn get_existing_l2oo_config(workspace_root: &Path) -> Result<L2OOConfig> {
    let zkconfig_path = workspace_root.join("contracts/zkl2ooconfig.json").canonicalize()?;
    if fs::metadata(&zkconfig_path).is_ok() {
        let zkconfig_str = fs::read_to_string(zkconfig_path)?;
        Ok(serde_json::from_str(&zkconfig_str)?)
    } else {
        bail!("Missing zkl2ooconfig.json");
    }
}

/// Write the L2OO rollup config to `contracts/zkl2ooconfig.json`.
fn write_l2oo_config(config: L2OOConfig, workspace_root: &Path) -> Result<()> {
    let zkconfig_path = workspace_root.join("contracts/zkl2ooconfig.json").canonicalize()?;
    // Write the L2OO rollup config to the zkl2ooconfig.json file.
    fs::write(zkconfig_path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

fn find_project_root() -> Option<PathBuf> {
    let mut path = std::env::current_dir().ok()?;
    while !path.join(".git").exists() {
        if !path.pop() {
            return None;
        }
    }
    Some(path)
}

#[tokio::main]
async fn main() -> Result<()> {
    // This fetches the .env file from the project root. If the command is invoked in the contracts/ directory,
    // the .env file in the root of the repo is used.
    if let Some(root) = find_project_root() {
        dotenv::from_path(root.join(".env")).ok();
    } else {
        eprintln!("Warning: Could not find project root. .env file not loaded.");
    }
    update_l2oo_config().await
}
