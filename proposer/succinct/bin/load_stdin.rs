use op_succinct_client_utils::boot::BootInfoStruct;
use sp1_sdk::{utils, SP1Stdin};
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    utils::setup_logger();
    // Read the artifact file
    // Claiming block 16544118
    let artifact_bytes = fs::read("artifact_01j6dxg0f7evpv9v7myf0q9xcd")?;

    // Deserialize the bytes into SP1Stdin
    let mut stdin: SP1Stdin = bincode::deserialize(&artifact_bytes)?;

    let boot = stdin.read::<BootInfoStruct>();

    println!("{:?}", boot);

    Ok(())
}
