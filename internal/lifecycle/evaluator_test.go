package lifecycle

import (
	"path/filepath"
	"testing"
)

func TestContractShapeAndCanonicalDecisions(t *testing.T) {
	root := filepath.Join("..", "..")
	policy, err := LoadPolicy(filepath.Join(root, ".gooo", "claim-evidence-lifecycle.gooo"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Evaluate(policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.Lifecycle.Counts.CanonicalCases != 12 {
		t.Fatalf("canonical cases = %d", result.Lifecycle.Counts.CanonicalCases)
	}
	if result.Lifecycle.Counts.Closed != 4 || result.Lifecycle.Counts.Unknown != 4 || result.Lifecycle.Counts.Refuted != 4 {
		t.Fatalf("counts = %+v", result.Lifecycle.Counts)
	}
	if result.Lifecycle.TombstoneCount != 12 || result.Lifecycle.ClaimDeletionCount != 0 {
		t.Fatalf("retention = %+v", result.Lifecycle)
	}
	if !result.Replay.ExactMatch || result.SemanticDigest == "" {
		t.Fatalf("replay = %+v", result.Replay)
	}
	for _, transition := range result.Transitions {
		if transition.Unknown != nil && CountUnknownFields(transition.Unknown) != 6 {
			t.Fatalf("unknown frontier = %+v", transition.Unknown)
		}
	}
}

func TestPrecedenceChoosesRefutedOverUnknown(t *testing.T) {
	policy := Policy{
		Module:     "test",
		Version:    "v1",
		Graph:      "test/v1",
		Precedence: []string{"REFUTED", "UNKNOWN", "CLOSED"},
		Terminals: []Terminal{{State: "REFUTED", Class: "REFUTED"}, {State: "UNKNOWN", Class: "UNKNOWN"}, {State: "SUPPORTED", Class: "CLOSED"}},
		Rules:      []Rule{{Signal: "contradiction", Outcome: "REFUTED"}, {Signal: "stale", Outcome: "UNKNOWN"}},
		Cases:      []Case{{ID: "x", Class: "REFUTED", Trigger: "contradiction", Signals: []string{"contradiction", "stale"}, Tombstone: true}},
		Ownership:  []string{"claim-state-machine", "evidence-admissibility", "subsumption-supersession", "tombstone-retention", "decision-precedence", "artifact-schema"},
	}
	state, decision, err := decide(policy, policy.Cases[0])
	if err != nil {
		t.Fatal(err)
	}
	if state != "REFUTED" || decision != "REFUTED" {
		t.Fatalf("state=%s decision=%s", state, decision)
	}
}
