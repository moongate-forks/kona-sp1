use std::fs;
use std::path::PathBuf;

use alloy::eips::eip1559::BaseFeeParams;
use alloy_primitives::Address;
use anyhow::Result;
use op_alloy_genesis::ChainGenesis;
use op_alloy_genesis::RollupConfig;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use toml::Value;

#[derive(Debug, Deserialize, Clone)]
pub struct ProposerConfig {
    pub l1_chain_id: u64,
    pub l2_chain_id: u64,
    pub l2oo_address: String,
    pub max_concurrent_proof_requests: u64,
    pub max_block_range_per_span_proof: u64,
    pub submission_interval: u64,
}

/// Parse the proposer config from the workspace root.
pub fn get_proposer_config(l2_chain_id: u64) -> Option<ProposerConfig> {
    let workspace_root = cargo_metadata::MetadataCommand::new()
        .exec()
        .expect("Failed to get workspace root")
        .workspace_root;
    let config_path = workspace_root.join("proposer.toml");
    let content = fs::read_to_string(config_path).ok()?;
    let value = content.parse::<Value>().ok()?;

    let mut config_map = HashMap::new();

    for (key, value) in value.as_table().unwrap() {
        let config = ProposerConfig {
            l1_chain_id: value["L1_CHAIN_ID"].as_integer().unwrap() as u64,
            l2_chain_id: value["L2_CHAIN_ID"].as_integer().unwrap() as u64,
            l2oo_address: value["L2OO_ADDRESS"].as_str().unwrap().to_string(),
            max_concurrent_proof_requests: value["MAX_CONCURRENT_PROOF_REQUESTS"]
                .as_integer()
                .unwrap() as u64,
            max_block_range_per_span_proof: value["MAX_BLOCK_RANGE_PER_SPAN_PROOF"]
                .as_integer()
                .unwrap() as u64,
            submission_interval: value["SUBMISSION_INTERVAL"].as_integer().unwrap() as u64,
        };
        let l2_chain_id = key.parse::<u64>().expect("Failed to parse L2 chain ID");
        config_map.insert(l2_chain_id, config);
    }

    config_map.get(&l2_chain_id).cloned()
}

/// Matches the output of the optimism_rollupConfig RPC call.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OptimismRollupConfigRPC {
    genesis: ChainGenesis,
    block_time: u64,
    max_sequencer_drift: u64,
    seq_window_size: u64,
    channel_timeout: u64,
    l1_chain_id: u64,
    l2_chain_id: u64,
    regolith_time: Option<u64>,
    canyon_time: Option<u64>,
    delta_time: Option<u64>,
    ecotone_time: Option<u64>,
    fjord_time: Option<u64>,
    granite_time: Option<u64>,
    holocene_time: Option<u64>,
    batch_inbox_address: Address,
    deposit_contract_address: Address,
    l1_system_config_address: Address,
    protocol_versions_address: Address,
    da_challenge_contract_address: Option<Address>,
}

/// The chain config returned by the `debug_chainConfig` RPC call.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChainConfig {
    chain_id: u64,
    homestead_block: u64,
    eip150_block: u64,
    eip155_block: u64,
    eip158_block: u64,
    byzantium_block: u64,
    constantinople_block: u64,
    petersburg_block: u64,
    istanbul_block: u64,
    muir_glacier_block: u64,
    berlin_block: u64,
    london_block: u64,
    arrow_glacier_block: u64,
    gray_glacier_block: u64,
    merge_netsplit_block: u64,
    shanghai_time: u64,
    cancun_time: u64,
    bedrock_block: u64,
    regolith_time: u64,
    canyon_time: u64,
    ecotone_time: u64,
    fjord_time: u64,
    terminal_total_difficulty: u64,
    terminal_total_difficulty_passed: bool,
    optimism: OptimismConfig,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OptimismConfig {
    eip1559_elasticity: u128,
    eip1559_denominator: u128,
    eip1559_denominator_canyon: u128,
}

/// Merge the rollup and chain configs.
pub(crate) fn merge_rollup_config(
    op_rollup_config_rpc: &OptimismRollupConfigRPC,
    chain: &ChainConfig,
) -> Result<RollupConfig> {
    let mut rollup_config = RollupConfig {
        genesis: op_rollup_config_rpc.genesis,
        block_time: op_rollup_config_rpc.block_time,
        max_sequencer_drift: op_rollup_config_rpc.max_sequencer_drift,
        seq_window_size: op_rollup_config_rpc.seq_window_size,
        channel_timeout: op_rollup_config_rpc.channel_timeout,
        l1_chain_id: op_rollup_config_rpc.l1_chain_id,
        l2_chain_id: op_rollup_config_rpc.l2_chain_id,
        regolith_time: op_rollup_config_rpc.regolith_time,
        canyon_time: op_rollup_config_rpc.canyon_time,
        delta_time: op_rollup_config_rpc.delta_time,
        ecotone_time: op_rollup_config_rpc.ecotone_time,
        fjord_time: op_rollup_config_rpc.fjord_time,
        granite_time: op_rollup_config_rpc.granite_time,
        holocene_time: op_rollup_config_rpc.holocene_time,
        batch_inbox_address: op_rollup_config_rpc.batch_inbox_address,
        deposit_contract_address: op_rollup_config_rpc.deposit_contract_address,
        l1_system_config_address: op_rollup_config_rpc.l1_system_config_address,
        protocol_versions_address: op_rollup_config_rpc.protocol_versions_address,
        da_challenge_address: op_rollup_config_rpc.da_challenge_contract_address,
        ..Default::default()
    };

    // Add the base fee params from the chain config.
    rollup_config.base_fee_params = BaseFeeParams {
        elasticity_multiplier: chain.optimism.eip1559_elasticity,
        max_change_denominator: chain.optimism.eip1559_denominator,
    };

    // Add the canyon base fee params from the chain config.
    rollup_config.canyon_base_fee_params = BaseFeeParams {
        elasticity_multiplier: chain.optimism.eip1559_elasticity,
        max_change_denominator: chain.optimism.eip1559_denominator_canyon,
    };

    Ok(rollup_config)
}

/// Save rollup config to the rollup config file.
pub fn save_rollup_config(rollup_config: &RollupConfig) -> Result<()> {
    let rollup_config_path = get_rollup_config_path(rollup_config.l2_chain_id)?;

    // Create the directory for the rollup config if it doesn't exist.
    let rollup_configs_dir = rollup_config_path.parent().unwrap();
    if !rollup_configs_dir.exists() {
        fs::create_dir_all(rollup_configs_dir)?;
    }

    // Write the rollup config to the file.
    let rollup_config_str = serde_json::to_string_pretty(rollup_config)?;
    fs::write(rollup_config_path, rollup_config_str)?;
    Ok(())
}

/// Get the path to the rollup config file for the given chain id.
pub fn get_rollup_config_path(l2_chain_id: u64) -> Result<PathBuf> {
    let workspace_root = cargo_metadata::MetadataCommand::new()
        .exec()
        .expect("Failed to get workspace root")
        .workspace_root;
    let rollup_config_path = workspace_root.join(format!("configs/{}/rollup.json", l2_chain_id));
    Ok(rollup_config_path.into())
}

/// Read rollup config from the rollup config file.
pub fn read_rollup_config(l2_chain_id: u64) -> Result<RollupConfig> {
    let rollup_config_path = get_rollup_config_path(l2_chain_id)?;
    let rollup_config_str = fs::read_to_string(rollup_config_path)?;
    let rollup_config: RollupConfig = serde_json::from_str(&rollup_config_str)?;
    Ok(rollup_config)
}
