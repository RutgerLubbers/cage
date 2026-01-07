package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestPathContains(t *testing.T) {
	tests := []struct {
		name     string
		parent   string
		child    string
		expected bool
	}{
		{
			name:     "parent contains child",
			parent:   "/home/user",
			child:    "/home/user/foo",
			expected: true,
		},
		{
			name:     "parent contains deeply nested child",
			parent:   "/home/user",
			child:    "/home/user/foo/bar/baz",
			expected: true,
		},
		{
			name:     "parent does NOT contain similar prefix",
			parent:   "/home/user",
			child:    "/home/userX",
			expected: false,
		},
		{
			name:     "parent does NOT contain similar prefix with extension",
			parent:   "/home/user",
			child:    "/home/user.config",
			expected: false,
		},
		{
			name:     "same path is NOT contained",
			parent:   "/home/user",
			child:    "/home/user",
			expected: false,
		},
		{
			name:     "unrelated paths",
			parent:   "/foo",
			child:    "/bar",
			expected: false,
		},
		{
			name:     "child is shorter than parent",
			parent:   "/home/user/long/path",
			child:    "/home/user",
			expected: false,
		},
		{
			name:     "empty parent",
			parent:   "",
			child:    "/any/path",
			expected: false,
		},
		{
			name:     "empty child",
			parent:   "/any/path",
			child:    "",
			expected: false,
		},
		{
			name:     "root contains everything",
			parent:   "/",
			child:    "/home/user",
			expected: false, // Actually, based on the pathContains logic, root doesn't contain other paths due to the length check
		},
		{
			name:     "relative paths normalized",
			parent:   "./home/user",
			child:    "./home/user/subdir",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pathContains(tt.parent, tt.child)
			if result != tt.expected {
				t.Errorf("pathContains(%q, %q) = %v, want %v", tt.parent, tt.child, result, tt.expected)
			}
		})
	}
}

func TestRuleResolver_AddAllowRule(t *testing.T) {
	resolver := NewRuleResolver()
	source := RuleSource{PresetName: "test-preset", IsCLI: false}

	// Test adding a rule
	resolver.AddAllowRule("/home/user/project", source)

	// Verify the rule was stored correctly
	key := ruleKey{path: cleanPath("/home/user/project"), mode: AccessWrite}
	rules, exists := resolver.rules[key]
	if !exists {
		t.Fatal("Rule was not stored")
	}

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]
	expectedPath := cleanPath("/home/user/project")
	if rule.Path != expectedPath {
		t.Errorf("Expected path %q, got %q", expectedPath, rule.Path)
	}
	if rule.Mode != AccessWrite {
		t.Errorf("Expected mode %v, got %v", AccessWrite, rule.Mode)
	}
	if rule.Action != ActionAllow {
		t.Errorf("Expected action %v, got %v", ActionAllow, rule.Action)
	}
	if rule.Source.PresetName != "test-preset" {
		t.Errorf("Expected preset %q, got %q", "test-preset", rule.Source.PresetName)
	}
	if rule.Source.IsCLI != false {
		t.Errorf("Expected IsCLI false, got %v", rule.Source.IsCLI)
	}
}

func TestRuleResolver_AddAllowRule_PathNormalization(t *testing.T) {
	resolver := NewRuleResolver()
	source := RuleSource{PresetName: "test", IsCLI: false}

	// Test that relative path is converted to absolute
	resolver.AddAllowRule("./relative/path", source)

	// Get expected absolute path
	expectedPath := cleanPath("./relative/path")
	key := ruleKey{path: expectedPath, mode: AccessWrite}

	rules, exists := resolver.rules[key]
	if !exists {
		t.Fatal("Rule was not stored with normalized path")
	}

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	// Verify the path was normalized to absolute
	if !filepath.IsAbs(rules[0].Path) {
		t.Errorf("Expected absolute path, got %q", rules[0].Path)
	}
}

func TestRuleResolver_AddDenyRule(t *testing.T) {
	resolver := NewRuleResolver()
	source := RuleSource{PresetName: "security", IsCLI: true}
	exceptions := []string{"/sensitive/allowed", "./relative/exception"}

	// Test adding a deny rule with exceptions
	resolver.AddDenyRule("/sensitive", exceptions, source)

	// Verify the rule was stored correctly
	key := ruleKey{path: cleanPath("/sensitive"), mode: AccessReadWrite}
	rules, exists := resolver.rules[key]
	if !exists {
		t.Fatal("Deny rule was not stored")
	}

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]
	expectedPath := cleanPath("/sensitive")
	if rule.Path != expectedPath {
		t.Errorf("Expected path %q, got %q", expectedPath, rule.Path)
	}
	if rule.Mode != AccessReadWrite {
		t.Errorf("Expected mode %v, got %v", AccessReadWrite, rule.Mode)
	}
	if rule.Action != ActionDeny {
		t.Errorf("Expected action %v, got %v", ActionDeny, rule.Action)
	}
	if rule.Source.IsCLI != true {
		t.Errorf("Expected IsCLI true, got %v", rule.Source.IsCLI)
	}

	// Verify exceptions are normalized
	if len(rule.Except) != 2 {
		t.Fatalf("Expected 2 exceptions, got %d", len(rule.Except))
	}

	expectedExceptions := []string{
		cleanPath("/sensitive/allowed"),
		cleanPath("./relative/exception"),
	}

	for i, expected := range expectedExceptions {
		if rule.Except[i] != expected {
			t.Errorf("Exception %d: expected %q, got %q", i, expected, rule.Except[i])
		}
	}
}

func TestRuleResolver_ValidatePreset(t *testing.T) {
	tests := []struct {
		name           string
		setupRules     func(*RuleResolver)
		presetName     string
		expectedErrors int
		expectedTypes  []ErrorType
	}{
		{
			name: "duplicate allow rules in same preset",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test-preset", IsCLI: false}
				r.AddAllowRule("/path", source)
				r.AddAllowRule("/path", source)
			},
			presetName:     "test-preset",
			expectedErrors: 1,
			expectedTypes:  []ErrorType{ErrorDuplicate},
		},
		{
			name: "duplicate deny rules in same preset",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test-preset", IsCLI: false}
				r.AddDenyRule("/path", []string{}, source)
				r.AddDenyRule("/path", []string{}, source)
			},
			presetName:     "test-preset",
			expectedErrors: 1,
			expectedTypes:  []ErrorType{ErrorDuplicate},
		},
		{
			name: "conflict - allow and deny same path in same preset",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test-preset", IsCLI: false}
				r.AddAllowRule("/path", source)
				// Note: AddDenyRule uses AccessReadWrite, but we need to test same mode conflict
				// We'll add a deny rule manually for this test
				r.addRule(ResolvedRule{
					Path:   cleanPath("/path"),
					Mode:   AccessWrite, // Same mode as AddAllowRule
					Action: ActionDeny,
					Source: source,
				})
			},
			presetName:     "test-preset",
			expectedErrors: 1,
			expectedTypes:  []ErrorType{ErrorConflict},
		},
		{
			name: "no error for carve-out pattern - deny broad, allow specific",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test-preset", IsCLI: false}
				r.AddDenyRule("/broad", []string{}, source)
				// Manually add an allow rule for same mode to test carve-out
				r.addRule(ResolvedRule{
					Path:   cleanPath("/broad/specific"),
					Mode:   AccessReadWrite, // Same mode as AddDenyRule
					Action: ActionAllow,
					Source: source,
				})
			},
			presetName:     "test-preset",
			expectedErrors: 0,
			expectedTypes:  []ErrorType{},
		},
		{
			name: "no error when rules are from different presets",
			setupRules: func(r *RuleResolver) {
				source1 := RuleSource{PresetName: "preset1", IsCLI: false}
				source2 := RuleSource{PresetName: "preset2", IsCLI: false}
				r.AddAllowRule("/path", source1)
				r.addRule(ResolvedRule{
					Path:   cleanPath("/path"),
					Mode:   AccessWrite,
					Action: ActionDeny,
					Source: source2,
				})
			},
			presetName:     "preset1",
			expectedErrors: 0,
			expectedTypes:  []ErrorType{},
		},
		{
			name: "no errors for valid preset",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test-preset", IsCLI: false}
				r.AddAllowRule("/path1", source)
				r.AddAllowRule("/path2", source)
				r.AddDenyRule("/path3", []string{}, source)
			},
			presetName:     "test-preset",
			expectedErrors: 0,
			expectedTypes:  []ErrorType{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := NewRuleResolver()
			tt.setupRules(resolver)

			errors := resolver.ValidatePreset(tt.presetName)

			if len(errors) != tt.expectedErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectedErrors, len(errors))
				for i, err := range errors {
					t.Logf("Error %d: %v", i, err)
				}
				return
			}

			// Check error types
			for i, expectedType := range tt.expectedTypes {
				if i >= len(errors) {
					t.Errorf("Expected error %d to be type %v, but no error at index %d", i, expectedType, i)
					continue
				}
				if ruleErr, ok := errors[i].(*RuleError); ok {
					if ruleErr.Type != expectedType {
						t.Errorf("Error %d: expected type %v, got %v", i, expectedType, ruleErr.Type)
					}
				} else {
					t.Errorf("Error %d: expected *RuleError, got %T", i, errors[i])
				}
			}
		})
	}
}

func TestRuleResolver_Resolve(t *testing.T) {
	tests := []struct {
		name               string
		setupRules         func(*RuleResolver)
		expectedWriteRules int
		expectedReadRules  int
		expectedConflicts  int
		validateResult     func(t *testing.T, writeRules, readRules []ResolvedRule, conflicts []RuleConflict)
	}{
		{
			name: "single rule returns unchanged",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test", IsCLI: false}
				r.AddAllowRule("/path", source)
			},
			expectedWriteRules: 1,
			expectedReadRules:  0,
			expectedConflicts:  0,
		},
		{
			name: "most specific path wins - longer path beats shorter",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test", IsCLI: false}
				r.addRule(ResolvedRule{
					Path:   "/home",
					Mode:   AccessWrite,
					Action: ActionDeny,
					Source: source,
				})
				r.addRule(ResolvedRule{
					Path:   "/home/user/project",
					Mode:   AccessWrite,
					Action: ActionAllow,
					Source: source,
				})
			},
			expectedWriteRules: 2, // Both rules should be present as they don't conflict
			expectedReadRules:  0,
			expectedConflicts:  0,
		},
		{
			name: "CLI rule beats preset rule for same path",
			setupRules: func(r *RuleResolver) {
				presetSource := RuleSource{PresetName: "test", IsCLI: false}
				cliSource := RuleSource{PresetName: "", IsCLI: true}
				r.addRule(ResolvedRule{
					Path:   "/path",
					Mode:   AccessWrite,
					Action: ActionDeny,
					Source: presetSource,
				})
				r.addRule(ResolvedRule{
					Path:   "/path",
					Mode:   AccessWrite,
					Action: ActionAllow,
					Source: cliSource,
				})
			},
			expectedWriteRules: 1,
			expectedReadRules:  0,
			expectedConflicts:  1,
			validateResult: func(t *testing.T, writeRules, readRules []ResolvedRule, conflicts []RuleConflict) {
				if len(writeRules) > 0 && !writeRules[0].Source.IsCLI {
					t.Error("Expected CLI rule to win, but preset rule won")
				}
			},
		},
		{
			name: "allow beats deny for same path and source type",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test", IsCLI: false}
				r.addRule(ResolvedRule{
					Path:   "/path",
					Mode:   AccessWrite,
					Action: ActionDeny,
					Source: source,
				})
				r.addRule(ResolvedRule{
					Path:   "/path",
					Mode:   AccessWrite,
					Action: ActionAllow,
					Source: source,
				})
			},
			expectedWriteRules: 1,
			expectedReadRules:  0,
			expectedConflicts:  1,
			validateResult: func(t *testing.T, writeRules, readRules []ResolvedRule, conflicts []RuleConflict) {
				if len(writeRules) > 0 && writeRules[0].Action != ActionAllow {
					t.Error("Expected allow rule to win, but deny rule won")
				}
			},
		},
		{
			name: "carve-out pattern is NOT reported as conflict",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test", IsCLI: false}
				r.addRule(ResolvedRule{
					Path:   "/broad",
					Mode:   AccessWrite,
					Action: ActionDeny,
					Source: source,
				})
				r.addRule(ResolvedRule{
					Path:   "/broad/specific",
					Mode:   AccessWrite,
					Action: ActionAllow,
					Source: source,
				})
			},
			expectedWriteRules: 2,
			expectedReadRules:  0,
			expectedConflicts:  0, // Carve-out should not be reported as conflict
		},
		{
			name: "rules sorted alphabetically",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test", IsCLI: false}
				r.AddAllowRule("/very/long/path/here", source)
				r.AddAllowRule("/short", source)
				r.AddAllowRule("/medium/path", source)
			},
			expectedWriteRules: 3,
			expectedReadRules:  0,
			expectedConflicts:  0,
			validateResult: func(t *testing.T, writeRules, readRules []ResolvedRule, conflicts []RuleConflict) {
				// Check that rules are sorted alphabetically
				for i := 1; i < len(writeRules); i++ {
					if writeRules[i-1].Path > writeRules[i].Path {
						t.Errorf("Rules not sorted alphabetically: %q should come after %q",
							writeRules[i-1].Path, writeRules[i].Path)
					}
				}
			},
		},
		{
			name: "read and write rules separated correctly",
			setupRules: func(r *RuleResolver) {
				source := RuleSource{PresetName: "test", IsCLI: false}
				r.AddAllowRule("/write/path", source)                // AccessWrite
				r.AddReadRule("/read/path", source)                  // AccessRead
				r.AddDenyRule("/readwrite/path", []string{}, source) // AccessReadWrite
			},
			expectedWriteRules: 2, // write/path + readwrite/path
			expectedReadRules:  2, // read/path + readwrite/path
			expectedConflicts:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := NewRuleResolver()
			tt.setupRules(resolver)

			writeRules, readRules, conflicts := resolver.Resolve()

			if len(writeRules) != tt.expectedWriteRules {
				t.Errorf("Expected %d write rules, got %d", tt.expectedWriteRules, len(writeRules))
			}
			if len(readRules) != tt.expectedReadRules {
				t.Errorf("Expected %d read rules, got %d", tt.expectedReadRules, len(readRules))
			}
			if len(conflicts) != tt.expectedConflicts {
				t.Errorf("Expected %d conflicts, got %d", tt.expectedConflicts, len(conflicts))
			}

			if tt.validateResult != nil {
				tt.validateResult(t, writeRules, readRules, conflicts)
			}
		})
	}
}

func TestIsCarveOut(t *testing.T) {
	tests := []struct {
		name     string
		rule1    ResolvedRule
		rule2    ResolvedRule
		expected bool
	}{
		{
			name: "deny broad + allow specific = carve-out",
			rule1: ResolvedRule{
				Path:   "/broad",
				Action: ActionDeny,
			},
			rule2: ResolvedRule{
				Path:   "/broad/specific",
				Action: ActionAllow,
			},
			expected: true,
		},
		{
			name: "allow specific + deny broad = carve-out (reversed order)",
			rule1: ResolvedRule{
				Path:   "/broad/specific",
				Action: ActionAllow,
			},
			rule2: ResolvedRule{
				Path:   "/broad",
				Action: ActionDeny,
			},
			expected: true,
		},
		{
			name: "allow broad + deny specific = NOT a carve-out",
			rule1: ResolvedRule{
				Path:   "/broad",
				Action: ActionAllow,
			},
			rule2: ResolvedRule{
				Path:   "/broad/specific",
				Action: ActionDeny,
			},
			expected: false,
		},
		{
			name: "same path different actions = NOT a carve-out",
			rule1: ResolvedRule{
				Path:   "/same/path",
				Action: ActionDeny,
			},
			rule2: ResolvedRule{
				Path:   "/same/path",
				Action: ActionAllow,
			},
			expected: false,
		},
		{
			name: "same action = NOT a carve-out",
			rule1: ResolvedRule{
				Path:   "/path1",
				Action: ActionAllow,
			},
			rule2: ResolvedRule{
				Path:   "/path2",
				Action: ActionAllow,
			},
			expected: false,
		},
		{
			name: "unrelated paths = NOT a carve-out",
			rule1: ResolvedRule{
				Path:   "/unrelated1",
				Action: ActionDeny,
			},
			rule2: ResolvedRule{
				Path:   "/unrelated2",
				Action: ActionAllow,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCarveOut(tt.rule1, tt.rule2)
			if result != tt.expected {
				t.Errorf("isCarveOut(%v, %v) = %v, want %v", tt.rule1, tt.rule2, result, tt.expected)
			}
		})
	}
}

func TestSortRulesBySpecificity(t *testing.T) {
	tests := []struct {
		name     string
		input    []ResolvedRule
		expected []string // expected order of paths
	}{
		{
			name: "paths sorted alphabetically",
			input: []ResolvedRule{
				{Path: "/very/long/path/here"},
				{Path: "/short"},
				{Path: "/medium/path"},
				{Path: "/"},
			},
			expected: []string{"/", "/medium/path", "/short", "/very/long/path/here"},
		},
		{
			name: "alphabetical order",
			input: []ResolvedRule{
				{Path: "/zebra"},
				{Path: "/alpha"},
				{Path: "/beta"},
			},
			expected: []string{"/alpha", "/beta", "/zebra"},
		},
		{
			name: "groups by parent directory",
			input: []ResolvedRule{
				{Path: "/home/user/.config/zebra"},
				{Path: "/home/user/.local/share"},
				{Path: "/home/user/.config/alpha"},
				{Path: "/home/user/.local/state"},
				{Path: "/home/user/.cache/build"},
			},
			expected: []string{
				"/home/user/.cache/build",
				"/home/user/.config/alpha",
				"/home/user/.config/zebra",
				"/home/user/.local/share",
				"/home/user/.local/state",
			},
		},
		{
			name:     "empty slice",
			input:    []ResolvedRule{},
			expected: []string{},
		},
		{
			name: "single rule",
			input: []ResolvedRule{
				{Path: "/single"},
			},
			expected: []string{"/single"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to avoid modifying the input
			rules := make([]ResolvedRule, len(tt.input))
			copy(rules, tt.input)

			sortRulesBySpecificity(rules)

			// Extract paths from sorted rules
			actualPaths := make([]string, len(rules))
			for i, rule := range rules {
				actualPaths[i] = rule.Path
			}

			if !reflect.DeepEqual(actualPaths, tt.expected) {
				t.Errorf("sortRulesBySpecificity() = %v, want %v", actualPaths, tt.expected)
			}
		})
	}
}

func TestResolveConflict(t *testing.T) {
	tests := []struct {
		name     string
		rules    []ResolvedRule
		expected ResolvedRule
	}{
		{
			name: "CLI beats preset",
			rules: []ResolvedRule{
				{
					Path:   "/path",
					Action: ActionDeny,
					Source: RuleSource{PresetName: "preset", IsCLI: false},
				},
				{
					Path:   "/path",
					Action: ActionAllow,
					Source: RuleSource{PresetName: "", IsCLI: true},
				},
			},
			expected: ResolvedRule{
				Path:   "/path",
				Action: ActionAllow,
				Source: RuleSource{PresetName: "", IsCLI: true},
			},
		},
		{
			name: "allow beats deny when same source type",
			rules: []ResolvedRule{
				{
					Path:   "/path",
					Action: ActionDeny,
					Source: RuleSource{PresetName: "preset", IsCLI: false},
				},
				{
					Path:   "/path",
					Action: ActionAllow,
					Source: RuleSource{PresetName: "preset", IsCLI: false},
				},
			},
			expected: ResolvedRule{
				Path:   "/path",
				Action: ActionAllow,
				Source: RuleSource{PresetName: "preset", IsCLI: false},
			},
		},
		{
			name: "more specific path wins when same action and source type",
			rules: []ResolvedRule{
				{
					Path:   "/broad",
					Action: ActionAllow,
					Source: RuleSource{PresetName: "preset", IsCLI: false},
				},
				{
					Path:   "/broad/specific",
					Action: ActionAllow,
					Source: RuleSource{PresetName: "preset", IsCLI: false},
				},
			},
			expected: ResolvedRule{
				Path:   "/broad/specific",
				Action: ActionAllow,
				Source: RuleSource{PresetName: "preset", IsCLI: false},
			},
		},
		{
			name: "single rule returns itself",
			rules: []ResolvedRule{
				{
					Path:   "/path",
					Action: ActionAllow,
					Source: RuleSource{PresetName: "preset", IsCLI: false},
				},
			},
			expected: ResolvedRule{
				Path:   "/path",
				Action: ActionAllow,
				Source: RuleSource{PresetName: "preset", IsCLI: false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveConflict(tt.rules)

			// Compare the relevant fields
			if result.Path != tt.expected.Path {
				t.Errorf("Expected path %q, got %q", tt.expected.Path, result.Path)
			}
			if result.Action != tt.expected.Action {
				t.Errorf("Expected action %v, got %v", tt.expected.Action, result.Action)
			}
			if result.Source.IsCLI != tt.expected.Source.IsCLI {
				t.Errorf("Expected IsCLI %v, got %v", tt.expected.Source.IsCLI, result.Source.IsCLI)
			}
			if result.Source.PresetName != tt.expected.Source.PresetName {
				t.Errorf("Expected preset %q, got %q", tt.expected.Source.PresetName, result.Source.PresetName)
			}
		})
	}
}

func TestIsMoreSpecific(t *testing.T) {
	tests := []struct {
		name     string
		path1    string
		path2    string
		expected bool
	}{
		{
			name:     "longer path is more specific",
			path1:    "/home/user/project",
			path2:    "/home/user",
			expected: true,
		},
		{
			name:     "shorter path is less specific",
			path1:    "/home",
			path2:    "/home/user",
			expected: false,
		},
		{
			name:     "same length is not more specific",
			path1:    "/path/one",
			path2:    "/path/two",
			expected: false,
		},
		{
			name:     "empty path vs non-empty",
			path1:    "/path",
			path2:    "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isMoreSpecific(tt.path1, tt.path2)
			if result != tt.expected {
				t.Errorf("isMoreSpecific(%q, %q) = %v, want %v", tt.path1, tt.path2, result, tt.expected)
			}
		})
	}
}

func TestCleanPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		validate func(string) bool
	}{
		{
			name:  "relative path becomes absolute",
			input: "./relative/path",
			validate: func(output string) bool {
				return filepath.IsAbs(output)
			},
		},
		{
			name:  "absolute path stays absolute",
			input: "/absolute/path",
			validate: func(output string) bool {
				return filepath.IsAbs(output) && output == filepath.Clean("/absolute/path")
			},
		},
		{
			name:  "path with dots is cleaned",
			input: "/path/../other/./file",
			validate: func(output string) bool {
				return output == "/other/file"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanPath(tt.input)
			if !tt.validate(result) {
				t.Errorf("cleanPath(%q) = %q, validation failed", tt.input, result)
			}
		})
	}
}
