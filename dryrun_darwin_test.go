//go:build darwin

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// Layer 3: Dry Run Display Tests (testing showDryRun output)

func TestDryRunDisplayShowsDuplicate(t *testing.T) {
	resolver := NewRuleResolver()
	resolver.AddDenyRule("/Users/test", []string{},
		RuleSource{PresetName: "builtin:secure"})

	writeRules, readRules, _ := resolver.Resolve()

	config := &SandboxConfig{
		WriteRules: writeRules,
		ReadRules:  readRules,
		Strict:     true,
		Command:    "test",
		Args:       []string{},
	}

	// Capture output
	var buf bytes.Buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := showDryRun(config)

	w.Close()
	os.Stdout = oldStdout
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("showDryRun failed: %v", err)
	}

	output := buf.String()

	// Count how many times the deny rule appears in the summary section
	// (not in the raw profile section)
	summarySection := strings.Split(output, "Raw profile:")[0]

	denyRuleCount := strings.Count(summarySection, "/Users/test (read+write)")

	t.Logf("Deny rule appears %d times in summary", denyRuleCount)

	if denyRuleCount == 2 {
		t.Log("BUG CONFIRMED: Deny rule appears twice in dry-run summary")
	}

	if denyRuleCount != 1 {
		t.Errorf("Deny rule should appear once in summary (currently fails - BUG), got %d", denyRuleCount)
	}
}
