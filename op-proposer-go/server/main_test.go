package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
	"github.com/succinctlabs/op-succinct-go/server/utils"
)

// This test fetches span batches for a recent block range and confirms that the number of span batches is non-zero.
// This is a sanity check to ensure that the span batch fetching logic is working correctly.
func TestHandleSpanBatchRanges(t *testing.T) {

	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		t.Fatalf("Error loading .env file: %v", err)
	}

	l2Rpc := os.Getenv("L2_RPC")
	l2Node := os.Getenv("L2_NODE_RPC")
	l1RPC := os.Getenv("L1_RPC")
	l1Beacon := os.Getenv("L1_BEACON_RPC")

	if l2Rpc == "" || l1RPC == "" || l1Beacon == "" {
		t.Fatalf("Required environment variables are not set")
	}

	// Rollup config
	rollupCfg, err := utils.GetRollupConfigFromL2Rpc(l2Rpc)
	if err != nil {
		t.Fatalf("Failed to get rollup config: %v", err)
	}

	// Get a recent block from the L2 RPC
	client, err := ethclient.Dial(l2Rpc)
	if err != nil {
		t.Fatalf("Failed to connect to L2 RPC: %v", err)
	}

	block, err := client.BlockNumber(context.Background())
	if err != nil {
		t.Fatalf("Failed to get block number: %v", err)
	}

	startBlock := block - 10000
	endBlock := block - 9000

	config := utils.BatchDecoderConfig{
		L2ChainID:    rollupCfg.L2ChainID,
		L2Node:       l2Node,
		L1RPC:        l1RPC,
		L1Beacon:     l1Beacon,
		BatchSender:  rollupCfg.Genesis.SystemConfig.BatcherAddr,
		L2StartBlock: startBlock,
		L2EndBlock:   endBlock,
		// TODO: Make directory specific to L2 chain. This avoids race conditions when multiple chains are running on the same machine.
		DataDir: fmt.Sprintf("/tmp/batch_decoder/%d/transactions_cache", rollupCfg.L2ChainID),
	}

	ranges, err := utils.GetAllSpanBatchesInBlockRange(config)
	if err != nil {
		t.Fatalf("Failed to get span batch ranges: %v", err)
	}

	// Check that the number of span batches is non-zero
	if len(ranges) == 0 {
		t.Errorf("Expected non-zero span batches, got 0")
	}

	// Print the number of span batches found
	t.Logf("Number of span batches found: %d", len(ranges))

	// Optionally, you can add more specific checks on the ranges returned
	for i, r := range ranges {
		t.Logf("Range %d: Start: %d, End: %d", i, r.Start, r.End)
	}
}
