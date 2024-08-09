use alloy_consensus::Header;
use alloy_primitives::B256;
use anyhow::Result;
use client_utils::RawBootInfo;
use host_utils::fetcher::{ChainMode, SP1KonaDataFetcher};

async fn get_earliest_l1_header(
    fetcher: &SP1KonaDataFetcher,
    boot_infos: &Vec<RawBootInfo>,
) -> Result<Header> {
    let mut earliest_block_num: u64 = u64::MAX;
    let mut earliest_l1_header: Option<Header> = None;

    for boot_info in boot_infos {
        let l1_block_header = fetcher
            .get_header_by_hash(ChainMode::L1, boot_info.l1_head)
            .await?;
        if l1_block_header.number < earliest_block_num {
            earliest_block_num = l1_block_header.number;
            earliest_l1_header = Some(l1_block_header);
        }
    }
    Ok(earliest_l1_header.unwrap())
}

pub async fn fetch_header_preimages(
    boot_infos: &Vec<RawBootInfo>,
    latest: B256,
) -> Result<Vec<Header>> {
    let fetcher = SP1KonaDataFetcher::new();

    // Get the earliest L1 Head from the boot_infos.
    let start_header = get_earliest_l1_header(&fetcher, boot_infos).await?;

    // Fetch the full header for the latest L1 Head (which is validated on chain).
    let mut curr_header = fetcher.get_header_by_hash(ChainMode::L1, latest).await?;

    // Walk back from the latest header until we reach the first header, getting all the preimages.
    let mut headers = Vec::new();
    while curr_header.number >= start_header.number {
        headers.push(curr_header.clone());
        curr_header = fetcher
            .get_header_by_hash(ChainMode::L1, curr_header.parent_hash)
            .await?;
    }

    // Reverse the headers to put them in order from start to end.
    headers.reverse();
    Ok(headers)
}
