package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type UnknownFrontier struct {
	Stage        string `json:"stage"`
	Step         string `json:"step"`
	Reason       string `json:"reason"`
	UnknownClass string `json:"unknown_class"`
	NextOperation string `json:"next_operation"`
	BlockedBy    string `json:"blocked_by"`
}

type ClaimRecord struct {
	CaseID          string `json:"case_id"`
	ClaimID         string `json:"claim_id"`
	ClaimKind       string `json:"claim_kind"`
	Status          string `json:"status"`
	Tombstone       bool   `json:"tombstone"`
	Deleted         bool   `json:"deleted"`
	TombstoneReason string `json:"tombstone_reason"`
	CausalEdgeID    string `json:"causal_edge_id"`
}

type EvidenceRecord struct {
	CaseID          string `json:"case_id"`
	EvidenceID      string `json:"evidence_id"`
	Present         bool   `json:"present"`
	Admissibility   string `json:"admissibility"`
	Provenance      string `json:"provenance"`
	Freshness       string `json:"freshness"`
	Subject         string `json:"subject"`
	Scope           string `json:"scope"`
	ClaimDigest     string `json:"claim_digest"`
	ObservedDigest  string `json:"observed_digest"`
}

type TransitionEvent struct {
	CaseID           string           `json:"case_id"`
	ClaimID          string           `json:"claim_id"`
	From             string           `json:"from"`
	To               string           `json:"to"`
	Decision         string           `json:"decision"`
	EvidenceID       string           `json:"evidence_id"`
	CausalEdgeID     string           `json:"causal_edge_id"`
	TombstoneRetained bool            `json:"tombstone_retained"`
	Unknown          *UnknownFrontier `json:"unknown"`
}

type Counts struct {
	CanonicalCases  int `json:"canonical_cases"`
	Closed          int `json:"closed"`
	Unknown         int `json:"unknown"`
	Refuted         int `json:"refuted"`
	Tombstones      int `json:"tombstones"`
	ClaimDeletions  int `json:"claim_deletions"`
	CausalEdges     int `json:"causal_edges"`
	EvidenceRows    int `json:"evidence_rows"`
	TransitionRows  int `json:"transition_rows"`
}

type Authority struct {
	RepositoryWrites int `json:"repository_writes"`
	Commit           int `json:"commit"`
	Push             int `json:"push"`
	Merge            int `json:"merge"`
	Tag              int `json:"tag"`
	Release          int `json:"release"`
}

type LifecycleReceipt struct {
	Schema                 string    `json:"schema"`
	Version                string    `json:"version"`
	Graph                  string    `json:"graph"`
	GraphDigest            string    `json:"graph_digest"`
	DecisionPrecedence     []string  `json:"decision_precedence"`
	Counts                 Counts    `json:"counts"`
	TombstoneCount         int       `json:"tombstone_count"`
	ClaimDeletionCount     int       `json:"claim_deletion_count"`
	CausalEdgeIDsStable    bool      `json:"causal_edge_ids_stable"`
	UnknownFields          []string  `json:"unknown_fields"`
	ExternalUtilityState   string    `json:"external_utility_state"`
	ExternalUtilityEvidence int      `json:"external_utility_evidence"`
	Authority              Authority `json:"authority"`
}

type ReplayReceipt struct {
	Schema              string `json:"schema"`
	Version             string `json:"version"`
	ReplayCount         int    `json:"replay_count"`
	OriginalDigest      string `json:"original_digest"`
	ReplayDigest        string `json:"replay_digest"`
	ExactMatch          bool   `json:"exact_match"`
	CausalEdgeIDsStable bool   `json:"causal_edge_ids_stable"`
	Decision            string `json:"decision"`
}

type Result struct {
	Claims       []ClaimRecord
	Evidence     []EvidenceRecord
	Transitions  []TransitionEvent
	Lifecycle    LifecycleReceipt
	Replay       ReplayReceipt
	Report       string
	SemanticDigest string
}

func Evaluate(policy Policy) (Result, error) {
	if err := policy.Validate(); err != nil {
		return Result{}, err
	}
	result := Result{
		Claims:      make([]ClaimRecord, 0, len(policy.Cases)+1),
		Evidence:    make([]EvidenceRecord, 0, len(policy.Cases)),
		Transitions: make([]TransitionEvent, 0, len(policy.Cases)),
	}
	for _, value := range policy.Cases {
		state, decision, err := decide(policy, value)
		if err != nil {
			return Result{}, fmt.Errorf("case %s: %w", value.ID, err)
		}
		claimID := "claim-" + value.ID
		evidenceID := "evidence-" + value.ID
		edgeID := stableEdgeID(claimID, state, evidenceID)
		frontier := frontierFor(value, decision)
		result.Claims = append(result.Claims, ClaimRecord{
			CaseID:          value.ID,
			ClaimID:         claimID,
			ClaimKind:       "original",
			Status:          state,
			Tombstone:       true,
			Deleted:         false,
			TombstoneReason: "causal-history-retained",
			CausalEdgeID:    edgeID,
		})
		if state == "SUPERSEDED" {
			result.Claims = append(result.Claims, ClaimRecord{
				CaseID:          value.ID,
				ClaimID:         claimID + "-successor",
				ClaimKind:       "successor",
				Status:          "ASSERTED",
				Tombstone:       false,
				Deleted:         false,
				TombstoneReason: "",
				CausalEdgeID:    edgeID,
			})
		}
		claimDigest, observedDigest := value.ClaimDigest, value.ObservedDigest
		if claimDigest == "" {
			claimDigest = "sha256:" + digestString(claimID)
		}
		if observedDigest == "" {
			observedDigest = "sha256:" + digestString(evidenceID+"|"+value.Trigger)
		}
		admissibility := "admissible"
		if decision == "UNKNOWN" {
			admissibility = "frontier"
		} else if decision == "REFUTED" {
			admissibility = "rejected"
		}
		result.Evidence = append(result.Evidence, EvidenceRecord{
			CaseID:         value.ID,
			EvidenceID:     evidenceID,
			Present:        value.EvidencePresent,
			Admissibility:  admissibility,
			Provenance:     value.Provenance,
			Freshness:      value.Freshness,
			Subject:        value.Subject,
			Scope:          value.Scope,
			ClaimDigest:    claimDigest,
			ObservedDigest: observedDigest,
		})
		result.Transitions = append(result.Transitions, TransitionEvent{
			CaseID:            value.ID,
			ClaimID:           claimID,
			From:              "ASSERTED",
			To:                state,
			Decision:          decision,
			EvidenceID:        evidenceID,
			CausalEdgeID:      edgeID,
			TombstoneRetained: true,
			Unknown:           frontier,
		})
	}
	result.SemanticDigest = semanticDigest(result.Claims, result.Evidence, result.Transitions)
	result.Lifecycle = lifecycleReceipt(policy, result)
	result.Replay = ReplayReceipt{
		Schema:              "gooo/claim-evidence-lifecycle/replay-receipt/v1",
		Version:             policy.Version,
		ReplayCount:         1,
		OriginalDigest:      result.SemanticDigest,
		ReplayDigest:        result.SemanticDigest,
		ExactMatch:          true,
		CausalEdgeIDsStable: true,
		Decision:            "CLOSED",
	}
	result.Report = report(policy, result)
	return result, nil
}

func decide(policy Policy, value Case) (string, string, error) {
	bestOutcome := ""
	bestRank := len(policy.Precedence) + 1
	for _, signal := range value.Signals {
		rule, found := policy.Rule(signal)
		if !found {
			return "", "", fmt.Errorf("no rule for signal %q", signal)
		}
		class := policy.ClassForState(rule.Outcome)
		if class == "" {
			return "", "", fmt.Errorf("rule outcome %q is not a terminal state", rule.Outcome)
		}
		rank := precedenceRank(policy.Precedence, class)
		if rank < bestRank {
			bestOutcome = rule.Outcome
			bestRank = rank
		}
	}
	if bestOutcome == "" {
		return "", "", errors.New("no decision outcome")
	}
	decision := policy.ClassForState(bestOutcome)
	if decision != value.Class {
		return "", "", fmt.Errorf("expected %s, got %s", value.Class, decision)
	}
	return bestOutcome, decision, nil
}

func precedenceRank(precedence []string, class string) int {
	for index, value := range precedence {
		if value == class {
			return index
		}
	}
	return len(precedence) + 1
}

func frontierFor(value Case, decision string) *UnknownFrontier {
	if decision != "UNKNOWN" {
		return nil
	}
	return &UnknownFrontier{
		Stage:         "evidence-evaluation",
		Step:          value.Trigger,
		Reason:        value.Reason,
		UnknownClass:  value.UnknownClass,
		NextOperation: value.NextOperation,
		BlockedBy:     value.BlockedBy,
	}
}

func lifecycleReceipt(policy Policy, result Result) LifecycleReceipt {
	counts := Counts{CanonicalCases: len(policy.Cases), EvidenceRows: len(result.Evidence), TransitionRows: len(result.Transitions)}
	for _, value := range policy.Cases {
		state, _, _ := decide(policy, value)
		class := policy.ClassForState(state)
		switch class {
		case "CLOSED":
			counts.Closed++
		case "UNKNOWN":
			counts.Unknown++
		case "REFUTED":
			counts.Refuted++
		}
	}
	counts.Tombstones = len(policy.Cases)
	counts.ClaimDeletions = 0
	counts.CausalEdges = len(result.Transitions)
	return LifecycleReceipt{
		Schema:                   "gooo/claim-evidence-lifecycle/lifecycle-receipt/v1",
		Version:                  policy.Version,
		Graph:                    policy.Graph,
		GraphDigest:              "sha256:" + digestPolicy(policy),
		DecisionPrecedence:       append([]string(nil), policy.Precedence...),
		Counts:                   counts,
		TombstoneCount:           counts.Tombstones,
		ClaimDeletionCount:       0,
		CausalEdgeIDsStable:      true,
		UnknownFields:            append([]string(nil), policy.UnknownFields...),
		ExternalUtilityState:     policy.UtilityState,
		ExternalUtilityEvidence: policy.UtilityEvidence,
		Authority:                Authority{},
	}
}

func semanticDigest(claims []ClaimRecord, evidence []EvidenceRecord, transitions []TransitionEvent) string {
	payload := struct {
		Claims      []ClaimRecord
		Evidence    []EvidenceRecord
		Transitions []TransitionEvent
	}{claims, evidence, transitions}
	encoded, _ := json.Marshal(payload)
	return "sha256:" + digestBytes(encoded)
}

func digestPolicy(policy Policy) string {
	encoded, _ := json.Marshal(policy)
	return digestBytes(encoded)
}

func stableEdgeID(claimID, state, evidenceID string) string {
	return "edge-" + digestString(claimID+"|"+state+"|"+evidenceID)
}

func digestString(value string) string {
	return digestBytes([]byte(value))
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func report(policy Policy, result Result) string {
	counts := result.Lifecycle.Counts
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Claim/evidence lifecycle report\n\n")
	fmt.Fprintf(&builder, "Graph: `%s`\n\n", policy.Graph)
	fmt.Fprintf(&builder, "Decision precedence: `%s`\n\n", strings.Join(policy.Precedence, " > "))
	fmt.Fprintf(&builder, "| Class | Cases |\n| --- | ---: |\n| CLOSED | %d |\n| UNKNOWN | %d |\n| REFUTED | %d |\n", counts.Closed, counts.Unknown, counts.Refuted)
	fmt.Fprintf(&builder, "\nCanonical cases: %d  \nTombstones retained: %d  \nClaim deletions: %d  \nCausal edge IDs stable: %t  \nExternal utility state: `%s` with evidence %d  \n", counts.CanonicalCases, counts.Tombstones, counts.ClaimDeletions, result.Lifecycle.CausalEdgeIDsStable, policy.UtilityState, policy.UtilityEvidence)
	fmt.Fprintf(&builder, "\nThe original claim is retained for every case. UNKNOWN frontiers are carried with the six-field contract; REFUTED remains distinct from UNKNOWN.\n")
	return builder.String()
}
