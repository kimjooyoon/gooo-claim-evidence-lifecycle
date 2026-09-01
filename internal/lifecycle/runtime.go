package lifecycle

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func Run(root, policyPath, outputDir, mode string) error {
	policy, err := LoadPolicy(policyPath)
	if err != nil {
		return err
	}
	if mode != "run" && mode != "conformance" && mode != "integration" {
		return fmt.Errorf("unsupported mode %q", mode)
	}
	var before string
	if mode == "integration" {
		before, err = Snapshot(root, outputDir)
		if err != nil {
			return fmt.Errorf("input snapshot before evaluation: %w", err)
		}
	}
	result, err := Evaluate(policy)
	if err != nil {
		return err
	}
	if err := WriteOutputs(policy, result, outputDir); err != nil {
		return err
	}
	if mode == "integration" {
		after, snapshotErr := Snapshot(root, outputDir)
		if snapshotErr != nil {
			return fmt.Errorf("input snapshot after evaluation: %w", snapshotErr)
		}
		if before != after {
			return errors.New("input repository changed during evaluation")
		}
	}
	return ValidateOutputs(policy, outputDir)
}

func WriteOutputs(policy Policy, result Result, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return fmt.Errorf("read output directory: %w", err)
	}
	if len(entries) != 0 {
		return errors.New("caller-owned output directory must be empty")
	}
	if len(policy.Artifacts) != 6 {
		return errors.New("caller-owned output schema is not exactly six artifacts")
	}
	claimName, _ := policy.Artifact("claim-ledger.ndjson")
	evidenceName, _ := policy.Artifact("evidence-ledger.ndjson")
	transitionName, _ := policy.Artifact("transition-events.ndjson")
	lifecycleName, _ := policy.Artifact("lifecycle-receipt.json")
	replayName, _ := policy.Artifact("replay-receipt.json")
	reportName, _ := policy.Artifact("report.md")
	if claimName.Name == "" || evidenceName.Name == "" || transitionName.Name == "" || lifecycleName.Name == "" || replayName.Name == "" || reportName.Name == "" {
		return errors.New("required caller-owned artifacts are missing from policy")
	}
	if err := writeNDJSON(filepath.Join(outputDir, claimName.Name), result.Claims); err != nil {
		return err
	}
	if err := writeNDJSON(filepath.Join(outputDir, evidenceName.Name), result.Evidence); err != nil {
		return err
	}
	if err := writeNDJSON(filepath.Join(outputDir, transitionName.Name), result.Transitions); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outputDir, lifecycleName.Name), result.Lifecycle); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outputDir, replayName.Name), result.Replay); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, reportName.Name), []byte(result.Report), 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func ValidateOutputs(policy Policy, outputDir string) error {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return fmt.Errorf("read generated output: %w", err)
	}
	want := make([]string, 0, len(policy.Artifacts))
	for _, artifact := range policy.Artifacts {
		want = append(want, artifact.Name)
	}
	sort.Strings(want)
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return fmt.Errorf("generated output contains directory %q", entry.Name())
		}
		got = append(got, entry.Name())
	}
	sort.Strings(got)
	if len(got) != len(want) {
		return fmt.Errorf("generated output count %d does not equal %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			return fmt.Errorf("generated output names %v do not equal %v", got, want)
		}
	}
	return nil
}

func writeNDJSON(path string, value any) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	encoder := json.NewEncoder(file)
	var rows []any
	switch typed := value.(type) {
	case []ClaimRecord:
		for _, row := range typed {
			rows = append(rows, row)
		}
	case []EvidenceRecord:
		for _, row := range typed {
			rows = append(rows, row)
		}
	case []TransitionEvent:
		for _, row := range typed {
			rows = append(rows, row)
		}
	default:
		_ = file.Close()
		return fmt.Errorf("unsupported ndjson value for %s", filepath.Base(path))
	}
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			_ = file.Close()
			return fmt.Errorf("write %s: %w", filepath.Base(path), err)
		}
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

func Snapshot(root, outputDir string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	out, err := filepath.Abs(outputDir)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root && isSkippedPath(path, root, out) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		fileHash, hashErr := fileDigest(path)
		if hashErr != nil {
			return hashErr
		}
		fmt.Fprintf(hash, "%s\x00%d\x00%s\n", strings.TrimPrefix(path, root+string(os.PathSeparator)), info.Size(), fileHash)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func isSkippedPath(path, root, output string) bool {
	if path == output || strings.HasPrefix(path, output+string(os.PathSeparator)) {
		return true
	}
	relative := strings.TrimPrefix(path, root+string(os.PathSeparator))
	parts := strings.Split(relative, string(os.PathSeparator))
	for _, part := range parts {
		if part == ".git" || part == ".cache" || part == "cache" || part == "vendor" || part == "output" {
			return true
		}
	}
	return false
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func CountUnknownFields(value *UnknownFrontier) int {
	if value == nil {
		return 0
	}
	fields := []string{value.Stage, value.Step, value.Reason, value.UnknownClass, value.NextOperation, value.BlockedBy}
	count := 0
	for _, field := range fields {
		if field != "" {
			count++
		}
	}
	return count
}

func ReadJSON(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(bufio.NewReader(file)).Decode(target)
}
