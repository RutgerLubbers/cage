package main

// AccessMode represents the type of file access
type AccessMode uint8

const (
	AccessRead      AccessMode = 1 << iota // Read access
	AccessWrite                            // Write access
	AccessReadWrite = AccessRead | AccessWrite
)

// SandboxConfig contains the configuration for running a command in a sandbox
type SandboxConfig struct {
	// AllowAll disables all restrictions (for testing/debugging)
	AllowAll bool

	// AllowKeychain allows access to the keychain (macOS only)
	AllowKeychain bool

	// Strict enables strict mode where "/" is NOT added to read allowlist
	// When true, only explicit read rules are readable
	Strict bool

	// WriteRules are the resolved write access rules
	WriteRules []ResolvedRule

	// ReadRules are the resolved read access rules
	ReadRules []ResolvedRule

	// Conflicts detected during rule resolution (for dry-run display)
	Conflicts []RuleConflict

	// Command is the command to execute
	Command string

	// Args are the arguments to pass to the command
	Args []string
}

// RunInSandbox executes the given command with sandbox restrictions
// This is implemented differently for each platform
func RunInSandbox(config *SandboxConfig) error {
	return runInSandbox(config)
}
