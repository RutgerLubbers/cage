//go:build darwin

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func runInSandbox(config *SandboxConfig) error {
	profile, err := generateSandboxProfile(config)
	if err != nil {
		return fmt.Errorf("generate sandbox profile: %w", err)
	}

	sandboxPath, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return fmt.Errorf("sandbox-exec not found: %w", err)
	}

	args := []string{"sandbox-exec", "-p", profile, config.Command}
	args = append(args, config.Args...)

	return syscall.Exec(sandboxPath, args, os.Environ())
}

func generateSandboxProfile(config *SandboxConfig) (string, error) {
	var profile bytes.Buffer

	profile.WriteString("(version 1)\n")
	profile.WriteString(`(import "system.sb")` + "\n")
	profile.WriteString("(allow default)\n")

	if config.AllowAll {
		return profile.String(), nil
	}

	// Deny all file writes by default
	profile.WriteString("(deny file-write*)\n")

	// Allow system temporary directories
	profile.WriteString(
		`(allow file-write* (regex #"^/private/var/folders/[^/]+/[^/]+/(C|T|0)($|/)"))` + "\n",
	)

	// Allow keychain access if requested
	if config.AllowKeychain {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home directory: %w", err)
		}
		fmt.Fprintf(&profile, `(allow file-write* (subpath "%s/Library/Keychains"))`+"\n", homeDir)
	}

	// Emit write deny rules first (sorted alphabetically, grouped by directory)
	for _, rule := range config.WriteRules {
		if rule.Action == ActionDeny {
			emitDenyRule(&profile, rule, AccessWrite)
		}
	}

	// Emit read denies for AccessReadWrite rules (applies in all modes)
	for _, rule := range config.WriteRules {
		if rule.Action == ActionDeny && rule.Mode&AccessRead != 0 {
			emitDenyRule(&profile, rule, AccessRead)
		}
	}

	// Emit write allow rules (more specific, so they come after denies)
	for _, rule := range config.WriteRules {
		if rule.Action == ActionAllow {
			escapedPath := escapePathForSandbox(rule.Path)
			fmt.Fprintf(&profile, "(allow file-write* (subpath \"%s\"))\n", escapedPath)
			fmt.Fprintf(&profile, "(allow file-write* (literal \"%s\"))\n", escapedPath)
		}
	}

	// Emit read carve-outs from deny rules (exceptions restore read access)
	for _, rule := range config.WriteRules {
		if rule.Action == ActionDeny {
			for _, exc := range rule.Except {
				escapedExc := escapePathForSandbox(exc)
				fmt.Fprintf(&profile, "(allow file-read-data (subpath \"%s\"))\n", escapedExc)
				fmt.Fprintf(&profile, "(allow file-read-data (literal \"%s\"))\n", escapedExc)
			}
		}
	}

	// Handle strict mode (explicit read allowlist)
	if config.Strict {
		// Use file-read-data instead of file-read* to allow stat/lstat (metadata)
		// while blocking actual file content reads. This enables path resolution
		// for tools like Node.js/npm that need to call lstat() on parent directories.
		profile.WriteString("(deny file-read-data)\n")

		// Allow reading root directory - required for process startup and path resolution
		profile.WriteString("(allow file-read-data (literal \"/\"))\n")

		// Emit read deny rules from ReadRules (for pure read denies in strict mode)
		for _, rule := range config.ReadRules {
			if rule.Action == ActionDeny {
				emitDenyRule(&profile, rule, AccessRead)
			}
		}

		// Emit read allow rules
		for _, rule := range config.ReadRules {
			if rule.Action == ActionAllow {
				escapedPath := escapePathForSandbox(rule.Path)
				fmt.Fprintf(&profile, "(allow file-read-data (subpath \"%s\"))\n", escapedPath)
				fmt.Fprintf(&profile, "(allow file-read-data (literal \"%s\"))\n", escapedPath)
			}
		}

		// Write-allowed paths also need read access
		for _, rule := range config.WriteRules {
			if rule.Action == ActionAllow {
				escapedPath := escapePathForSandbox(rule.Path)
				fmt.Fprintf(&profile, "(allow file-read-data (subpath \"%s\"))\n", escapedPath)
				fmt.Fprintf(&profile, "(allow file-read-data (literal \"%s\"))\n", escapedPath)
			}
		}

		// Emit read carve-outs from read deny rules
		for _, rule := range config.ReadRules {
			if rule.Action == ActionDeny {
				for _, exc := range rule.Except {
					escapedExc := escapePathForSandbox(exc)
					fmt.Fprintf(&profile, "(allow file-read-data (subpath \"%s\"))\n", escapedExc)
					fmt.Fprintf(&profile, "(allow file-read-data (literal \"%s\"))\n", escapedExc)
				}
			}
		}
	}

	return profile.String(), nil
}

// emitDenyRule emits a deny rule for the specified access mode.
//
// For read denies, we use file-read-data instead of file-read* to allow
// stat/lstat operations (file-read-metadata) while blocking actual file content reads.
// This is necessary because tools like Node.js/npm need to call lstat() on parent
// directories during path resolution, even for paths they don't need to read.
//
// Security model with file-read-data:
//   - stat/lstat (metadata): ALLOWED - needed for path resolution
//   - readdir (ls): BLOCKED - can't enumerate directory contents
//   - read (cat): BLOCKED - can't read file contents
func emitDenyRule(profile *bytes.Buffer, rule ResolvedRule, mode AccessMode) {
	modeStr := "file-write*"
	if mode == AccessRead {
		// Use file-read-data instead of file-read* to allow stat/lstat
		// while still blocking actual file content reads
		modeStr = "file-read-data"
	}

	if rule.IsGlob {
		regexPattern := globToSBPLRegex(rule.Path)
		fmt.Fprintf(profile, "(deny %s (regex #\"%s\"))\n", modeStr, regexPattern)
	} else {
		escapedPath := escapePathForSandbox(rule.Path)
		fmt.Fprintf(profile, "(deny %s (subpath \"%s\"))\n", modeStr, escapedPath)
	}
}

func escapePathForSandbox(path string) string {
	path = strings.ReplaceAll(path, "\\", "\\\\")
	path = strings.ReplaceAll(path, "\"", "\\\"")
	return path
}

func globToSBPLRegex(pattern string) string {
	var result strings.Builder
	result.WriteString("^")

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				result.WriteString(".*")
				i++
			} else {
				result.WriteString("[^/]*")
			}
		case '?':
			result.WriteString("[^/]")
		case '.', '(', ')', '[', ']', '{', '}', '+', '^', '$', '|', '\\':
			result.WriteByte('\\')
			result.WriteByte(c)
		default:
			result.WriteByte(c)
		}
	}

	result.WriteString("($|/)")
	return result.String()
}
