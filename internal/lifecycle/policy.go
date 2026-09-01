package lifecycle

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Binding struct {
	Activity string
	Node     string
}

type Terminal struct {
	State string
	Class string
}

type Rule struct {
	Signal  string
	Outcome string
}

type Artifact struct {
	Name  string
	Media string
}

type Metric struct {
	Phase  string
	Fields []string
}

type Case struct {
	ID              string
	Class           string
	Trigger         string
	Signals         []string
	EvidencePresent bool
	Provenance      string
	Freshness       string
	Subject         string
	Scope           string
	ClaimDigest     string
	ObservedDigest  string
	UnknownClass    string
	NextOperation   string
	BlockedBy       string
	Reason          string
	Tombstone       bool
}

type Policy struct {
	Module          string
	Version         string
	Graph           string
	Ownership       []string
	Activities      []string
	Bindings        []Binding
	States          []string
	Terminals       []Terminal
	Precedence      []string
	UnknownFields   []string
	Rules           []Rule
	Artifacts       []Artifact
	Metrics         []Metric
	Cases           []Case
	UtilityEvidence int
	UtilityState    string
}

func LoadPolicy(path string) (Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return Policy{}, fmt.Errorf("open policy: %w", err)
	}
	defer file.Close()

	var policy Policy
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		attrs := map[string]string{}
		needsAttributes := fields[0] == "binding" || fields[0] == "terminal" || fields[0] == "rule" || fields[0] == "artifact" || fields[0] == "external-utility" || fields[0] == "case"
		if needsAttributes {
			parsed, parseErr := attributes(fields[1:])
			if parseErr != nil {
				return Policy{}, fmt.Errorf("policy line %d: %w", lineNumber, parseErr)
			}
			attrs = parsed
		}
		switch fields[0] {
		case "module":
			if len(fields) != 3 || !strings.HasPrefix(fields[2], "version=") {
				return Policy{}, fmt.Errorf("policy line %d: malformed module", lineNumber)
			}
			policy.Module = fields[1]
			policy.Version = strings.TrimPrefix(fields[2], "version=")
		case "graph":
			if len(fields) != 2 {
				return Policy{}, fmt.Errorf("policy line %d: malformed graph", lineNumber)
			}
			policy.Graph = fields[1]
		case "ownership":
			if len(fields) != 2 {
				return Policy{}, fmt.Errorf("policy line %d: malformed ownership", lineNumber)
			}
			policy.Ownership = append(policy.Ownership, fields[1])
		case "activity":
			if len(fields) != 2 {
				return Policy{}, fmt.Errorf("policy line %d: malformed activity", lineNumber)
			}
			policy.Activities = append(policy.Activities, fields[1])
		case "binding":
			policy.Bindings = append(policy.Bindings, Binding{Activity: attrs["activity"], Node: attrs["node"]})
		case "state":
			if len(fields) != 2 {
				return Policy{}, fmt.Errorf("policy line %d: malformed state", lineNumber)
			}
			policy.States = append(policy.States, fields[1])
		case "terminal":
			policy.Terminals = append(policy.Terminals, Terminal{State: attrs["state"], Class: attrs["class"]})
		case "precedence":
			if len(fields) < 2 {
				return Policy{}, fmt.Errorf("policy line %d: malformed precedence", lineNumber)
			}
			policy.Precedence = append(policy.Precedence, fields[1:]...)
		case "unknown-fields":
			if len(fields) < 2 {
				return Policy{}, fmt.Errorf("policy line %d: malformed unknown-fields", lineNumber)
			}
			policy.UnknownFields = append(policy.UnknownFields, fields[1:]...)
		case "rule":
			policy.Rules = append(policy.Rules, Rule{Signal: attrs["signal"], Outcome: attrs["outcome"]})
		case "artifact":
			policy.Artifacts = append(policy.Artifacts, Artifact{Name: attrs["name"], Media: attrs["media"]})
		case "metric":
			if len(fields) < 3 {
				return Policy{}, fmt.Errorf("policy line %d: malformed metric", lineNumber)
			}
			policy.Metrics = append(policy.Metrics, Metric{Phase: fields[1], Fields: fields[2:]})
		case "external-utility":
			policy.UtilityState = attrs["state"]
			var parseErr error
			policy.UtilityEvidence, parseErr = strconv.Atoi(attrs["evidence"])
			if parseErr != nil {
				return Policy{}, fmt.Errorf("policy line %d: malformed utility evidence", lineNumber)
			}
		case "case":
			caseValue, parseErr := parseCase(attrs)
			if parseErr != nil {
				return Policy{}, fmt.Errorf("policy line %d: %w", lineNumber, parseErr)
			}
			policy.Cases = append(policy.Cases, caseValue)
		default:
			return Policy{}, fmt.Errorf("policy line %d: unknown directive %q", lineNumber, fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func attributes(fields []string) (map[string]string, error) {
	result := make(map[string]string, len(fields))
	for _, field := range fields {
		key, value, found := strings.Cut(field, "=")
		if !found || key == "" || value == "" {
			return nil, fmt.Errorf("malformed attribute %q", field)
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate attribute %q", key)
		}
		result[key] = value
	}
	return result, nil
}

func parseCase(attrs map[string]string) (Case, error) {
	value := Case{
		ID:            attrs["id"],
		Class:         attrs["class"],
		Trigger:       attrs["trigger"],
		Provenance:    attrs["provenance"],
		Freshness:     attrs["freshness"],
		Subject:       attrs["subject"],
		Scope:         attrs["scope"],
		ClaimDigest:   attrs["claim-digest"],
		ObservedDigest: attrs["observed-digest"],
		UnknownClass:  attrs["unknown_class"],
		NextOperation: attrs["next_operation"],
		BlockedBy:     attrs["blocked_by"],
		Reason:        attrs["reason"],
	}
	if value.UnknownClass == "" {
		value.UnknownClass = attrs["unknown-class"]
	}
	if value.NextOperation == "" {
		value.NextOperation = attrs["next-operation"]
	}
	if value.BlockedBy == "" {
		value.BlockedBy = attrs["blocked-by"]
	}
	var err error
	value.EvidencePresent, err = strconv.ParseBool(attrs["evidence-present"])
	if err != nil {
		return Case{}, errors.New("case evidence-present must be true or false")
	}
	value.Tombstone, err = strconv.ParseBool(attrs["tombstone"])
	if err != nil {
		return Case{}, errors.New("case tombstone must be true or false")
	}
	signals := attrs["signals"]
	if signals == "" {
		return Case{}, errors.New("case signals is required")
	}
	value.Signals = strings.Split(signals, ",")
	for _, signal := range value.Signals {
		if signal == "" {
			return Case{}, errors.New("case contains empty signal")
		}
	}
	return value, nil
}

func (p Policy) Validate() error {
	if p.Module == "" || p.Version == "" || p.Graph == "" {
		return errors.New("policy module, version, and graph are required")
	}
	if p.Graph != p.Module+"/"+p.Version {
		return errors.New("released graph identity does not match module")
	}
	if err := exactUnique(p.Ownership, []string{"claim-state-machine", "evidence-admissibility", "subsumption-supersession", "tombstone-retention", "decision-precedence", "artifact-schema"}); err != nil {
		return fmt.Errorf("ownership: %w", err)
	}
	if len(p.Activities) != 10 || !unique(p.Activities) {
		return errors.New("released graph must contain exactly ten unique activities")
	}
	if len(p.Bindings) != 10 {
		return errors.New("released graph must contain exactly ten activity bindings")
	}
	bindingCount := make(map[string]int, len(p.Bindings))
	for _, binding := range p.Bindings {
		if binding.Activity == "" || binding.Node == "" {
			return errors.New("activity binding has an empty field")
		}
		bindingCount[binding.Activity]++
	}
	for _, activity := range p.Activities {
		if bindingCount[activity] != 1 {
			return fmt.Errorf("activity %q is not bound exactly once", activity)
		}
	}
	if len(p.States) != 5 || !unique(p.States) {
		return errors.New("state machine must contain exactly five unique states")
	}
	if err := exactUnique(p.Precedence, []string{"REFUTED", "UNKNOWN", "CLOSED"}); err != nil {
		return fmt.Errorf("precedence: %w", err)
	}
	if err := exactUnique(p.UnknownFields, []string{"stage", "step", "reason", "unknown_class", "next_operation", "blocked_by"}); err != nil {
		return fmt.Errorf("unknown fields: %w", err)
	}
	if len(p.Artifacts) != 6 {
		return errors.New("artifact schema must contain exactly six artifacts")
	}
	artifactNames := make([]string, 0, len(p.Artifacts))
	for _, artifact := range p.Artifacts {
		if artifact.Name == "" || artifact.Media == "" {
			return errors.New("artifact has an empty field")
		}
		artifactNames = append(artifactNames, artifact.Name)
	}
	if !unique(artifactNames) {
		return errors.New("artifact names must be unique")
	}
	if err := exactUnique(artifactNames, []string{"claim-ledger.ndjson", "evidence-ledger.ndjson", "transition-events.ndjson", "lifecycle-receipt.json", "replay-receipt.json", "report.md"}); err != nil {
		return fmt.Errorf("artifact names: %w", err)
	}
	if len(p.Metrics) != 5 {
		return errors.New("metric schema must contain five phases")
	}
	for _, metric := range p.Metrics {
		if metric.Phase == "" || len(metric.Fields) != 2 || metric.Fields[0] != "wall_ms" || metric.Fields[1] != "peak_rss_kib" {
			return errors.New("each metric phase must declare wall_ms and peak_rss_kib")
		}
	}
	if p.UtilityEvidence != 0 || p.UtilityState != "UNKNOWN" {
		return errors.New("external utility evidence must remain UNKNOWN when absent")
	}
	if len(p.Cases) != 12 {
		return errors.New("canonical case catalog must contain exactly twelve cases")
	}
	caseIDs := make([]string, 0, len(p.Cases))
	classCounts := make(map[string]int)
	for _, value := range p.Cases {
		if value.ID == "" || value.Class == "" || value.Trigger == "" || len(value.Signals) == 0 {
			return errors.New("case has a required field missing")
		}
		if !value.Tombstone {
			return fmt.Errorf("case %q must retain its tombstone", value.ID)
		}
		caseIDs = append(caseIDs, value.ID)
		classCounts[value.Class]++
		if value.Class == "UNKNOWN" {
			if value.UnknownClass == "" || value.NextOperation == "" || value.BlockedBy == "" || value.Reason == "" {
				return fmt.Errorf("unknown case %q must carry its frontier fields", value.ID)
			}
		}
	}
	if !unique(caseIDs) || classCounts["CLOSED"] != 4 || classCounts["UNKNOWN"] != 4 || classCounts["REFUTED"] != 4 {
		return errors.New("canonical cases must be four CLOSED, four UNKNOWN, and four REFUTED")
	}
	if err := exactUnique(caseIDs, []string{
		"supported-evidence", "explicit-supersession", "replay", "stable-tombstone",
		"missing-evidence", "stale-evidence", "ambiguous-subject", "unbounded-scope",
		"counterexample", "digest-contradiction", "silent-claim-deletion", "evidence-without-provenance",
	}); err != nil {
		return fmt.Errorf("canonical case IDs: %w", err)
	}
	if len(p.Rules) == 0 {
		return errors.New("decision rules are required")
	}
	for _, rule := range p.Rules {
		if rule.Signal == "" || rule.Outcome == "" {
			return errors.New("rule has an empty field")
		}
	}
	return nil
}

func exactUnique(values, expected []string) error {
	if len(values) != len(expected) || !unique(values) {
		return fmt.Errorf("expected exactly %v", expected)
	}
	left := append([]string(nil), values...)
	right := append([]string(nil), expected...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] != right[index] {
			return fmt.Errorf("expected exactly %v", expected)
		}
	}
	return nil
}

func unique(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func (p Policy) Rule(signal string) (Rule, bool) {
	for _, rule := range p.Rules {
		if rule.Signal == signal {
			return rule, true
		}
	}
	return Rule{}, false
}

func (p Policy) ClassForState(state string) string {
	for _, terminal := range p.Terminals {
		if terminal.State == state {
			return terminal.Class
		}
	}
	return ""
}

func (p Policy) Artifact(name string) (Artifact, bool) {
	for _, artifact := range p.Artifacts {
		if artifact.Name == name {
			return artifact, true
		}
	}
	return Artifact{}, false
}
