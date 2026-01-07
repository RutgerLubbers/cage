//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestGenerateSandboxProfile_DenyUsesFileReadData(t *testing.T) {
	// Verify that deny rules use file-read-data instead of file-read*
	// This allows stat/lstat (metadata) while blocking actual file reads
	config := &SandboxConfig{
		WriteRules: []ResolvedRule{
			{
				Path:   "/Users/test",
				Action: ActionDeny,
				Mode:   AccessReadWrite,
			},
		},
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile failed: %v", err)
	}

	// Should use file-read-data, NOT file-read*
	if strings.Contains(profile, "(deny file-read* (subpath \"/Users/test\"))") {
		t.Error("Profile should NOT use file-read* for deny rules (blocks stat/lstat)")
	}
	if !strings.Contains(profile, "(deny file-read-data (subpath \"/Users/test\"))") {
		t.Error("Profile should use file-read-data for deny rules (allows stat/lstat)")
	}

	// Write deny should still use file-write*
	if !strings.Contains(profile, "(deny file-write* (subpath \"/Users/test\"))") {
		t.Error("Profile should use file-write* for write deny rules")
	}
}

func TestGenerateSandboxProfile_StrictModeUsesFileReadData(t *testing.T) {
	// Verify strict mode uses file-read-data and includes root literal
	config := &SandboxConfig{
		Strict: true,
		ReadRules: []ResolvedRule{
			{
				Path:   "/usr",
				Action: ActionAllow,
				Mode:   AccessRead,
			},
		},
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile failed: %v", err)
	}

	// Should use file-read-data for global deny, NOT file-read*
	if strings.Contains(profile, "(deny file-read*)") && !strings.Contains(profile, "(deny file-read-data)") {
		t.Error("Strict mode should use (deny file-read-data), not (deny file-read*)")
	}
	if !strings.Contains(profile, "(deny file-read-data)") {
		t.Error("Strict mode should include (deny file-read-data)")
	}

	// Must include root literal for process startup
	if !strings.Contains(profile, `(allow file-read-data (literal "/"))`) {
		t.Error("Strict mode must include (allow file-read-data (literal \"/\")) for process startup")
	}

	// Allow rules should use file-read-data
	if !strings.Contains(profile, `(allow file-read-data (subpath "/usr"))`) {
		t.Error("Strict mode allow rules should use file-read-data")
	}
}

func TestGenerateSandboxProfile_AllowAllDisablesRestrictions(t *testing.T) {
	config := &SandboxConfig{
		AllowAll: true,
		WriteRules: []ResolvedRule{
			{Path: "/should/be/ignored", Action: ActionDeny, Mode: AccessReadWrite},
		},
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile failed: %v", err)
	}

	// Should NOT contain any deny rules
	if strings.Contains(profile, "(deny file") {
		t.Error("AllowAll should disable all deny rules")
	}

	// Should have basic profile setup
	if !strings.Contains(profile, "(version 1)") {
		t.Error("Profile should include version")
	}
	if !strings.Contains(profile, "(allow default)") {
		t.Error("Profile should include allow default")
	}
}

func TestGenerateSandboxProfile_CarveOutsUseFileReadData(t *testing.T) {
	// Verify that carve-outs (exceptions) use file-read-data
	config := &SandboxConfig{
		WriteRules: []ResolvedRule{
			{
				Path:   "/Users/test",
				Action: ActionDeny,
				Mode:   AccessReadWrite,
				Except: []string{"/Users/test/allowed"},
			},
		},
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile failed: %v", err)
	}

	// Carve-outs should use file-read-data
	if !strings.Contains(profile, `(allow file-read-data (subpath "/Users/test/allowed"))`) {
		t.Error("Carve-outs should use file-read-data")
	}
}

func TestGenerateSandboxProfile_WriteRulesUseFileWriteStar(t *testing.T) {
	// Verify write rules still use file-write* (no change)
	config := &SandboxConfig{
		WriteRules: []ResolvedRule{
			{
				Path:   "/Users/test/project",
				Action: ActionAllow,
				Mode:   AccessWrite,
			},
		},
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile failed: %v", err)
	}

	// Write allows should use file-write*
	if !strings.Contains(profile, `(allow file-write* (subpath "/Users/test/project"))`) {
		t.Error("Write allow rules should use file-write*")
	}
}

func TestGenerateSandboxProfile_GlobDenyPattern(t *testing.T) {
	config := &SandboxConfig{
		WriteRules: []ResolvedRule{
			{
				Path:   "/Users/*/secret",
				Action: ActionDeny,
				Mode:   AccessReadWrite,
				IsGlob: true,
			},
		},
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile failed: %v", err)
	}

	// Glob patterns should use regex and file-read-data for read deny
	if !strings.Contains(profile, "(deny file-read-data (regex") {
		t.Error("Glob read deny should use file-read-data with regex")
	}
	if !strings.Contains(profile, "(deny file-write* (regex") {
		t.Error("Glob write deny should use file-write* with regex")
	}
}

func TestEmitDenyRule_ReadUsesFileReadData(t *testing.T) {
	tests := []struct {
		name     string
		mode     AccessMode
		isGlob   bool
		wantOp   string
		dontWant string
	}{
		{
			name:     "read deny uses file-read-data",
			mode:     AccessRead,
			isGlob:   false,
			wantOp:   "file-read-data",
			dontWant: "file-read*",
		},
		{
			name:     "write deny uses file-write*",
			mode:     AccessWrite,
			isGlob:   false,
			wantOp:   "file-write*",
			dontWant: "file-write-data",
		},
		{
			name:     "glob read deny uses file-read-data",
			mode:     AccessRead,
			isGlob:   true,
			wantOp:   "file-read-data",
			dontWant: "file-read*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ResolvedRule{
				Path:   "/test/path",
				Action: ActionDeny,
				Mode:   tt.mode,
				IsGlob: tt.isGlob,
			}

			var buf strings.Builder
			// Convert to bytes.Buffer for emitDenyRule
			// We need to use the actual function, so let's generate a profile instead
			config := &SandboxConfig{
				WriteRules: []ResolvedRule{rule},
			}

			profile, err := generateSandboxProfile(config)
			if err != nil {
				t.Fatalf("generateSandboxProfile failed: %v", err)
			}

			_ = buf // unused, we use profile directly

			if !strings.Contains(profile, tt.wantOp) {
				t.Errorf("Expected profile to contain %q", tt.wantOp)
			}
			// Only check dontWant for deny rules with the specific mode
			if tt.mode == AccessRead && strings.Contains(profile, "(deny "+tt.dontWant) {
				t.Errorf("Profile should NOT contain deny with %q", tt.dontWant)
			}
		})
	}
}

// Layer 2: Sandbox Profile Generation Tests (testing duplication in generateSandboxProfile)

func TestSandboxProfileDuplicateDenyInStrictMode(t *testing.T) {
	resolver := NewRuleResolver()

	// Add a deny rule with exceptions
	resolver.AddDenyRule("/Users/test", []string{
		"/Users/test/.bashrc",
		"/Users/test/.zshrc",
	}, RuleSource{PresetName: "builtin:secure"})

	writeRules, readRules, _ := resolver.Resolve()

	config := &SandboxConfig{
		WriteRules: writeRules,
		ReadRules:  readRules,
		Strict:     true, // Important: strict mode processes readRules
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile failed: %v", err)
	}

	// Count occurrences of write deny
	writeDenyCount := strings.Count(profile, `(deny file-write* (subpath "/Users/test"))`)
	if writeDenyCount != 1 {
		t.Errorf("Write deny should appear exactly once, got %d", writeDenyCount)
	}

	// Count occurrences of read deny - THIS IS WHERE THE BUG SHOWS
	readDenyCount := strings.Count(profile, `(deny file-read-data (subpath "/Users/test"))`)

	t.Logf("Read deny appears %d times", readDenyCount)

	if readDenyCount == 2 {
		t.Log("BUG CONFIRMED: Read deny appears twice in sandbox profile")
		t.Log("Once from writeRules iteration (line 64)")
		t.Log("Once from readRules iteration (line 102)")
	}

	// This assertion will FAIL, confirming the bug
	if readDenyCount != 1 {
		t.Errorf("Read deny should appear exactly once (currently fails - BUG), got %d", readDenyCount)
	}
}

func TestSandboxProfileNoDuplicateWithoutStrictMode(t *testing.T) {
	resolver := NewRuleResolver()
	resolver.AddDenyRule("/Users/test", []string{},
		RuleSource{PresetName: "builtin:secure"})

	writeRules, readRules, _ := resolver.Resolve()

	config := &SandboxConfig{
		WriteRules: writeRules,
		ReadRules:  readRules,
		Strict:     false, // No strict mode - readRules not processed
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile failed: %v", err)
	}

	// Count occurrences
	readDenyCount := strings.Count(profile, `(deny file-read-data (subpath "/Users/test"))`)

	// Should only appear once (from writeRules)
	if readDenyCount != 1 {
		t.Errorf("Without strict mode, read deny should appear exactly once, got %d", readDenyCount)
	}
}

func TestSandboxProfileWithCorrectedRules(t *testing.T) {
	resolver := NewRuleResolver()
	resolver.AddDenyRule("/Users/test", []string{},
		RuleSource{PresetName: "builtin:secure"})

	writeRules, readRules, _ := resolver.Resolve()

	// MANUALLY FIX: Remove AccessReadWrite deny rules from readRules
	correctedReadRules := []ResolvedRule{}
	for _, rule := range readRules {
		if rule.Action == ActionDeny && rule.Mode == AccessReadWrite {
			// Skip it - should only be in writeRules
			continue
		}
		correctedReadRules = append(correctedReadRules, rule)
	}

	config := &SandboxConfig{
		WriteRules: writeRules,
		ReadRules:  correctedReadRules, // Use corrected list
		Strict:     true,
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile failed: %v", err)
	}

	readDenyCount := strings.Count(profile, `(deny file-read-data (subpath "/Users/test"))`)

	if readDenyCount != 1 {
		t.Errorf("With corrected rules, read deny should appear exactly once, got %d", readDenyCount)
	}
}
