package main

import (
	"path/filepath"
	"sort"
	"strings"
)

// cleanPath normalizes a path by converting to absolute and cleaning it
func cleanPath(path string) string {
	// Convert to absolute path if not already
	absPath, err := filepath.Abs(path)
	if err != nil {
		// If filepath.Abs fails, use the original path
		absPath = path
	}

	// Clean the path to remove . and .. elements
	return filepath.Clean(absPath)
}

// RuleAction represents the action to take for a rule
type RuleAction int

const (
	ActionAllow RuleAction = iota
	ActionDeny
)

// RuleSource tracks where a rule came from
type RuleSource struct {
	PresetName string // e.g., "builtin:secure", "my-preset", or "" for CLI
	IsCLI      bool   // true if from command-line flag
}

// ResolvedRule represents a resolved file access rule
type ResolvedRule struct {
	Path   string
	Mode   AccessMode // from sandbox.go
	Action RuleAction // Allow or Deny
	Source RuleSource
	IsGlob bool
	Except []string // for deny rules with carve-outs
}

// RuleConflict represents a conflict between rules
type RuleConflict struct {
	Path         string
	Rules        []ResolvedRule // the conflicting rules
	Resolution   ResolvedRule   // which rule won
	IsSamePreset bool           // true if conflict within one preset
}

// RuleResolver resolves rules from multiple sources with conflict detection
type RuleResolver struct {
	// Map of (path, mode) -> list of rules
	rules map[ruleKey][]ResolvedRule
}

// ruleKey uniquely identifies a rule by path and access mode
type ruleKey struct {
	path string
	mode AccessMode
}

// NewRuleResolver creates a new rule resolver
func NewRuleResolver() *RuleResolver {
	return &RuleResolver{
		rules: make(map[ruleKey][]ResolvedRule),
	}
}

// AddAllowRule adds an allow rule for write access
func (r *RuleResolver) AddAllowRule(path string, source RuleSource) {
	normalizedPath := cleanPath(path)
	r.addRule(ResolvedRule{
		Path:   normalizedPath,
		Mode:   AccessWrite,
		Action: ActionAllow,
		Source: source,
		IsGlob: strings.Contains(path, "*"),
	})
}

// AddDenyRule adds a deny rule for read+write access
func (r *RuleResolver) AddDenyRule(path string, except []string, source RuleSource) {
	normalizedPath := cleanPath(path)

	// Clean exception paths
	cleanExcept := make([]string, len(except))
	for i, excPath := range except {
		cleanExcept[i] = cleanPath(excPath)
	}

	r.addRule(ResolvedRule{
		Path:   normalizedPath,
		Mode:   AccessReadWrite,
		Action: ActionDeny,
		Source: source,
		IsGlob: strings.Contains(path, "*"),
		Except: cleanExcept,
	})
}

// AddReadRule adds an allow rule for read access (used in strict mode)
func (r *RuleResolver) AddReadRule(path string, source RuleSource) {
	normalizedPath := cleanPath(path)
	r.addRule(ResolvedRule{
		Path:   normalizedPath,
		Mode:   AccessRead,
		Action: ActionAllow,
		Source: source,
		IsGlob: strings.Contains(path, "*"),
	})
}

// addRule adds a rule to the resolver
func (r *RuleResolver) addRule(rule ResolvedRule) {
	key := ruleKey{path: rule.Path, mode: rule.Mode}
	r.rules[key] = append(r.rules[key], rule)
}

// ValidatePreset validates a single preset for internal conflicts and duplicates
func (r *RuleResolver) ValidatePreset(presetName string) []error {
	var errors []error
	presetRules := make(map[ruleKey][]ResolvedRule)

	// Collect all rules from this preset
	for key, rules := range r.rules {
		for _, rule := range rules {
			if rule.Source.PresetName == presetName {
				presetRules[key] = append(presetRules[key], rule)
			}
		}
	}

	// Check for conflicts within this preset
	for _, rules := range presetRules {
		if len(rules) <= 1 {
			continue
		}

		// Check for exact duplicates (same path, mode, action)
		for i, rule1 := range rules {
			for j := i + 1; j < len(rules); j++ {
				rule2 := rules[j]
				if rule1.Action == rule2.Action {
					// Exact duplicate
					errors = append(errors, &RuleError{
						Type:    ErrorDuplicate,
						Message: "duplicate rule",
						Path:    rule1.Path,
						Mode:    rule1.Mode,
						Preset:  presetName,
					})
					continue
				}

				// Check if this is a carve-out situation
				if !isCarveOut(rule1, rule2) {
					// Real conflict: same path, different actions, not a carve-out
					errors = append(errors, &RuleError{
						Type:    ErrorConflict,
						Message: "conflicting actions for same path",
						Path:    rule1.Path,
						Mode:    rule1.Mode,
						Preset:  presetName,
					})
				}
			}
		}
	}

	return errors
}

// RuleError represents a rule validation error
type RuleError struct {
	Type    ErrorType
	Message string
	Path    string
	Mode    AccessMode
	Preset  string
}

func (e *RuleError) Error() string {
	return e.Message
}

// ErrorType represents the type of rule error
type ErrorType int

const (
	ErrorDuplicate ErrorType = iota
	ErrorConflict
)

// Resolve resolves all rules and detects conflicts
func (r *RuleResolver) Resolve() (writeRules, readRules []ResolvedRule, conflicts []RuleConflict) {
	writeRules = []ResolvedRule{}
	readRules = []ResolvedRule{}
	conflicts = []RuleConflict{}

	// Process each unique path+mode combination
	for key, rules := range r.rules {
		if len(rules) == 0 {
			continue
		}

		if len(rules) == 1 {
			// No conflict, add the rule
			rule := rules[0]
			if key.mode&AccessWrite != 0 {
				writeRules = append(writeRules, rule)
			}
			if key.mode&AccessRead != 0 && key.mode != AccessWrite {
				// Only add to readRules if it's pure read or read+write but not just write
				readRules = append(readRules, rule)
			}
			continue
		}

		// Multiple rules for the same path+mode - resolve conflict
		winner := resolveConflict(rules)

		// Detect if this is a same-preset conflict
		isSamePreset := true
		firstPreset := rules[0].Source.PresetName
		for _, rule := range rules[1:] {
			if rule.Source.PresetName != firstPreset {
				isSamePreset = false
				break
			}
		}

		// Only report as conflict if it's not a carve-out situation
		hasRealConflict := false
		for i, rule1 := range rules {
			for j := i + 1; j < len(rules); j++ {
				rule2 := rules[j]
				if rule1.Action != rule2.Action && !isCarveOut(rule1, rule2) {
					hasRealConflict = true
					break
				}
			}
			if hasRealConflict {
				break
			}
		}

		if hasRealConflict {
			conflicts = append(conflicts, RuleConflict{
				Path:         key.path,
				Rules:        rules,
				Resolution:   winner,
				IsSamePreset: isSamePreset,
			})
		}

		// Add the winning rule
		if key.mode&AccessWrite != 0 {
			writeRules = append(writeRules, winner)
		}
		if key.mode&AccessRead != 0 && key.mode != AccessWrite {
			readRules = append(readRules, winner)
		}
	}

	// Sort rules by path specificity (shortest path first for emission order)
	sortRulesBySpecificity(writeRules)
	sortRulesBySpecificity(readRules)

	return writeRules, readRules, conflicts
}

// resolveConflict resolves a conflict between multiple rules using precedence rules
func resolveConflict(rules []ResolvedRule) ResolvedRule {
	if len(rules) == 0 {
		panic("resolveConflict called with empty rules")
	}

	if len(rules) == 1 {
		return rules[0]
	}

	// Sort by precedence: CLI > preset, allow > deny, more specific path > less specific
	sort.Slice(rules, func(i, j int) bool {
		rule1, rule2 := rules[i], rules[j]

		// CLI beats preset
		if rule1.Source.IsCLI != rule2.Source.IsCLI {
			return rule1.Source.IsCLI // CLI wins
		}

		// Allow beats deny
		if rule1.Action != rule2.Action {
			return rule1.Action == ActionAllow // Allow wins
		}

		// More specific path beats less specific
		return isMoreSpecific(rule1.Path, rule2.Path)
	})

	return rules[0] // Return highest precedence rule
}

// isCarveOut checks if rule2 is a carve-out of rule1
// A carve-out is when we have a broad deny with a specific allow inside it
func isCarveOut(rule1, rule2 ResolvedRule) bool {
	if rule1.Action == ActionDeny && rule2.Action == ActionAllow {
		// Check if rule2's path is contained within rule1's path
		return pathContains(rule1.Path, rule2.Path)
	}
	if rule2.Action == ActionDeny && rule1.Action == ActionAllow {
		// Check if rule1's path is contained within rule2's path
		return pathContains(rule2.Path, rule1.Path)
	}
	return false
}

// pathContains checks if child path is contained within parent path
func pathContains(parent, child string) bool {
	parent = cleanPath(parent)
	child = cleanPath(child)

	// Child must be longer than parent to be contained
	if len(child) <= len(parent) {
		return false
	}

	// Child must start with parent
	if !strings.HasPrefix(child, parent) {
		return false
	}

	// The character after the parent path must be a path separator
	// This prevents "/home/user" from containing "/home/userX"
	if len(child) > len(parent) && child[len(parent)] != '/' {
		return false
	}

	return true
}

// isMoreSpecific returns true if path1 is more specific than path2
// More specific means longer path (deeper in hierarchy)
func isMoreSpecific(path1, path2 string) bool {
	return len(path1) > len(path2)
}

// sortRulesBySpecificity sorts rules alphabetically by path
// This groups paths by parent directory for readability while maintaining
// correct sandbox behavior (deny rules are emitted first separately)
func sortRulesBySpecificity(rules []ResolvedRule) {
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Path < rules[j].Path
	})
}
