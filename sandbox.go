package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

// AccessMode represents the type of file access
type AccessMode uint8

const (
	AccessRead      AccessMode = 1 << iota // Read access
	AccessWrite                            // Write access
	AccessReadWrite = AccessRead | AccessWrite
)

// DenyRule represents a path that should be denied access
type DenyRule struct {
	Pattern string     // The path pattern (may contain globs on macOS)
	Modes   AccessMode // Which access modes to deny
	IsGlob  bool       // True if pattern contains wildcards (only effective on macOS)
	Except  []string   // Paths to exclude from this deny rule (carve-outs)
}

// SandboxConfig contains the configuration for running a command in a sandbox
type SandboxConfig struct {
	// AllowAll disables all restrictions (for testing/debugging)
	AllowAll bool

	// AllowKeychain allows access to the keychain
	// This is only applicable on macOS
	AllowKeychain bool

	// AllowGit allows access to git common directory
	// This enables git operations in worktrees
	AllowGit bool

	// AllowedPaths are paths where write access is granted (existing behavior)
	AllowedPaths []string

	// Strict enables strict mode where "/" is NOT added to read allowlist
	// When true, only explicit ReadPaths are readable
	Strict bool

	// ReadPaths are paths where read access is explicitly granted
	// Only used when Strict is true
	ReadPaths []string

	// DenyRules are paths that should be denied access
	// On Linux, only write denies are effective (Landlock is allowlist-only)
	// On macOS, both read and write denies are effective
	DenyRules []DenyRule

	// Command is the command to execute
	Command string

	// Args are the arguments to pass to the command
	Args []string
}

func modifySandboxConfig(config *SandboxConfig) {
	pathSet := make(map[string]struct{})
	for _, path := range config.AllowedPaths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			absPath = path
		}
		pathSet[absPath] = struct{}{}
	}

	// Add git common directory if allowGit is enabled and not already handled by preset
	if config.AllowGit {
		gitCommonDir, err := getGitCommonDir()
		if err != nil {
			// Only warn on unexpected errors (not "not a git repo")
			fmt.Fprintf(os.Stderr, "warning: --allow-git: %v\n", err)
		} else if gitCommonDir != "" {
			pathSet[gitCommonDir] = struct{}{}
		}
		// If gitCommonDir is empty, we're not in a git repo - silently ignore
	}

	config.AllowedPaths = slices.Sorted(maps.Keys(pathSet))
}

// RunInSandbox executes the given command with sandbox restrictions
// This is implemented differently for each platform
func RunInSandbox(config *SandboxConfig) error {
	modifySandboxConfig(config)
	return runInSandbox(config)
}
