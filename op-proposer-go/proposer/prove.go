package proposer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/ethereum-optimism/optimism/op-proposer/proposer/db/ent"
	"github.com/ethereum-optimism/optimism/op-proposer/proposer/db/ent/proofrequest"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

func (l *L2OutputSubmitter) ProcessPendingProofs() error {
	failedReqs, err := l.db.GetProofsFailedOnServer()
	if err != nil {
		return fmt.Errorf("failed to get proofs failed on server: %w", err)
	}
	for _, req := range failedReqs {
		err = l.RetryRequest(req)
		if err != nil {
			return fmt.Errorf("failed to retry request: %w", err)
		}
	}

	reqs, err := l.db.GetAllPendingProofs()
	if err != nil {
		return err
	}
	l.Log.Info("Got all pending proofs from DB.", "count", len(reqs))
	for _, req := range reqs {
		status, proof, err := l.GetProofStatus(req.ProverRequestID)
		if err != nil {
			l.Log.Error("failed to get proof status", "err", err)
			return err
		}
		if status == "PROOF_FULFILLED" {
			// update the proof to the DB and update status to "COMPLETE"
			l.Log.Info("proof fulfilled", "id", req.ProverRequestID)
			err = l.db.AddProof(req.ID, proof)
			if err != nil {
				l.Log.Error("failed to update completed proof status", "err", err)
				return err
			}
			continue
		}

		timeout := uint64(time.Now().Unix()) > req.ProofRequestTime+l.DriverSetup.Cfg.ProofTimeout
		if timeout || status == "PROOF_UNCLAIMED" {
			// update status in db to "FAILED"
			l.Log.Info("proof timed out", "id", req.ProverRequestID)
			err = l.db.UpdateProofStatus(req.ID, "FAILED")
			if err != nil {
				l.Log.Error("failed to update failed proof status", "err", err)
				return err
			}

			err = l.RetryRequest(req)
			if err != nil {
				return fmt.Errorf("failed to retry request: %w", err)
			}
		}
	}

	return nil
}

func (l *L2OutputSubmitter) RetryRequest(req *ent.ProofRequest) error {
	// If an AGG proof failed, we're in trouble.
	// Try again.
	if req.Type == proofrequest.TypeAGG {
		l.Log.Error("agg proof failed, adding to db to retry", "req", req)

		err := l.db.NewEntryWithReqAddedTimestamp("AGG", req.StartBlock, req.EndBlock, 0)
		if err != nil {
			l.Log.Error("failed to add new proof request", "err")
			return err
		}
	}

	// If a SPAN proof failed, assume it was too big.
	// Therefore, create two new entries for the original proof split in half.
	l.Log.Info("span proof failed, splitting in half to retry", "req", req)
	tmpStart := req.StartBlock
	tmpEnd := tmpStart + ((req.EndBlock - tmpStart) / 2)
	for i := 0; i < 2; i++ {
		err := l.db.NewEntryWithReqAddedTimestamp("SPAN", tmpStart, tmpEnd, 0)
		if err != nil {
			l.Log.Error("failed to add new proof request", "err", err)
			return err
		}

		tmpStart = tmpEnd + 1
		tmpEnd = req.EndBlock
	}

	return nil
}

func (l *L2OutputSubmitter) RequestQueuedProofs(ctx context.Context) error {
	nextProofToRequest, err := l.db.GetNextUnrequestedProof()
	if err != nil {
		return fmt.Errorf("failed to get unrequested proofs: %w", err)
	}
	if nextProofToRequest == nil {
		return nil
	}

	if nextProofToRequest.Type == proofrequest.TypeAGG {
		if nextProofToRequest.L1BlockHash == "" {
			blockNumber, blockHash, err := l.checkpointBlockHash(ctx)
			if err != nil {
				l.Log.Error("failed to checkpoint block hash", "err", err)
				return err
			}
			nextProofToRequest, err = l.db.AddL1BlockInfoToAggRequest(nextProofToRequest.StartBlock, nextProofToRequest.EndBlock, blockNumber, blockHash.Hex())
			if err != nil {
				l.Log.Error("failed to add L1 block info to AGG request", "err", err)
			}

			// wait for the next loop so that we have the version with the block info added
			return nil
		} else {
			l.Log.Info("found agg proof with already checkpointed l1 block info")
		}
	} else {
		currentRequestedProofs, err := l.db.CountRequestedProofs()
		if err != nil {
			return fmt.Errorf("failed to count requested proofs: %w", err)
		}
		if currentRequestedProofs >= int(l.Cfg.MaxConcurrentProofRequests) {
			l.Log.Info("max concurrent proof requests reached, waiting for next cycle")
			return nil
		}
	}
	go func(p ent.ProofRequest) {
		l.Log.Info("requesting proof from server", "proof", p)
		err = l.db.UpdateProofStatus(nextProofToRequest.ID, "REQ")
		if err != nil {
			l.Log.Error("failed to update proof status", "err", err)
			return
		}

		err = l.RequestKonaProof(p)
		if err != nil {
			l.Log.Error("failed to request proof from Kona SP1", "err", err, "proof", p)
			err = l.db.UpdateProofStatus(nextProofToRequest.ID, "FAILED")
			if err != nil {
				l.Log.Error("failed to revert proof status", "err", err, "proverRequestID", nextProofToRequest.ID)
			}
		}
	}(*nextProofToRequest)

	return nil
}

// Use the L2OO contract to look up the range of blocks that the next proof must cover.
// Check the DB to see if we have sufficient span proofs to request an agg proof that covers this range.
// If so, queue up the agg proof in the DB to be requested later.
func (l *L2OutputSubmitter) DeriveAggProofs(ctx context.Context) error {
	latest, err := l.l2ooContract.LatestBlockNumber(&bind.CallOpts{Context: ctx})
	if err != nil {
		return fmt.Errorf("failed to get latest L2OO output: %w", err)
	}
	from := latest.Uint64() + 1

	minTo, err := l.l2ooContract.NextBlockNumber(&bind.CallOpts{Context: ctx})
	if err != nil {
		return fmt.Errorf("failed to get next L2OO output: %w", err)
	}

	created, end, err := l.db.TryCreateAggProofFromSpanProofs(from, minTo.Uint64())
	if err != nil {
		return fmt.Errorf("failed to create agg proof from span proofs: %w", err)
	}
	if created {
		l.Log.Info("created new AGG proof", "from", from, "to", end)
	}

	return nil
}

func (l *L2OutputSubmitter) RequestKonaProof(p ent.ProofRequest) error {
	prevConfirmedBlock := p.StartBlock - 1
	var proofId string
	var err error

	if p.Type == proofrequest.TypeAGG {
		proofId, err = l.RequestAggProof(prevConfirmedBlock, p.EndBlock, p.L1BlockHash)
		if err != nil {
			return fmt.Errorf("failed to request AGG proof: %w", err)
		}
	} else if p.Type == proofrequest.TypeSPAN {
		proofId, err = l.RequestSpanProof(prevConfirmedBlock, p.EndBlock)
		if err != nil {
			return fmt.Errorf("failed to request SPAN proof: %w", err)
		}
	} else {
		return fmt.Errorf("unknown proof type: %s", p.Type)
	}

	err = l.db.SetProverRequestID(p.ID, proofId)
	if err != nil {
		return fmt.Errorf("failed to set prover request ID: %w", err)
	}

	return nil
}

type SpanProofRequest struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

type AggProofRequest struct {
	Subproofs [][]byte `json:"subproofs"`
	L1Head    string   `json:"head"`
}
type ProofResponse struct {
	ProofID string `json:"proof_id"`
}

func (l *L2OutputSubmitter) RequestSpanProof(start, end uint64) (string, error) {
	l.Log.Info("requesting span proof", "start", start, "end", end)
	requestBody := SpanProofRequest{
		Start: start,
		End:   end,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return l.RequestProofFromServer("request_span_proof", jsonBody)
}

func (l *L2OutputSubmitter) RequestAggProof(start, end uint64, l1BlockHash string) (string, error) {
	l.Log.Info("requesting agg proof", "start", start, "end", end)
	subproofs, err := l.db.GetSubproofs(start+1, end)
	if err != nil {
		return "", fmt.Errorf("failed to get subproofs: %w", err)
	}
	requestBody := AggProofRequest{
		Subproofs: subproofs,
		L1Head:    l1BlockHash,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return l.RequestProofFromServer("request_agg_proof", jsonBody)
}

func (l *L2OutputSubmitter) RequestProofFromServer(urlPath string, jsonBody []byte) (string, error) {
	req, err := http.NewRequest("POST", l.Cfg.KonaServerUrl+"/"+urlPath, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 3 * time.Minute,
	}
	resp, err := client.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", fmt.Errorf("request timed out after 3 minutes: %w", err)
		}
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading the response body: %v", err)
	}

	// Create a variable of the Response type
	var response ProofResponse

	// Unmarshal the JSON into the response variable
	err = json.Unmarshal(body, &response)
	if err != nil {
		return "", fmt.Errorf("error decoding JSON response: %v", err)
	}
	l.Log.Info("successfully submitted proof", "proofID", response.ProofID)

	return response.ProofID, nil
}

type ProofStatus struct {
	Status string `json:"status"`
	Proof  []byte `json:"proof"`
}

func (l *L2OutputSubmitter) GetProofStatus(proofId string) (string, []byte, error) {
	req, err := http.NewRequest("GET", l.Cfg.KonaServerUrl+"/status/"+proofId, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return "", nil, fmt.Errorf("request timed out after 30 seconds: %w", err)
		}
		return "", nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Errorf("Error reading the response body: %v", err)
	}

	// Create a variable of the Response type
	var response ProofStatus

	// Unmarshal the JSON into the response variable
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Errorf("Error decoding JSON response: %v", err)
	}

	return response.Status, response.Proof, nil
}
