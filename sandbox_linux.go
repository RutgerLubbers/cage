//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func runInSandbox(config *SandboxConfig) error {
	if config.AllowAll {
		path, err := exec.LookPath(config.Command)
		if err != nil {
			return fmt.Errorf("command not found: %w", err)
		}
		argv := append([]string{config.Command}, config.Args...)
		return syscall.Exec(path, argv, os.Environ())
	}

	var rules []landlock.Rule

	if config.Strict {
		for _, rule := range config.ReadRules {
			if rule.Action == ActionAllow {
				absPath, err := filepath.Abs(rule.Path)
				if err != nil {
					absPath = rule.Path
				}
				if info, err := os.Stat(absPath); err == nil && info.IsDir() {
					rules = append(rules, landlock.RODirs(absPath))
				} else if err == nil {
					rules = append(rules, landlock.ROFiles(absPath))
				}
			}
		}

		for _, rule := range config.WriteRules {
			if rule.Action == ActionAllow {
				absPath, err := filepath.Abs(rule.Path)
				if err != nil {
					absPath = rule.Path
				}
				if info, err := os.Stat(absPath); err == nil && info.IsDir() {
					rules = append(rules, landlock.RODirs(absPath))
				} else if err == nil {
					rules = append(rules, landlock.ROFiles(absPath))
				}
			}
		}
	} else {
		rules = append(rules, landlock.RODirs("/"))

		for _, rule := range config.ReadRules {
			if rule.Action == ActionDeny && rule.Mode&AccessRead != 0 {
				if rule.IsGlob {
					fmt.Fprintf(os.Stderr,
						"cage: warning: glob pattern %q cannot be enforced on Linux "+
							"(Landlock requires literal paths); pattern will be ignored\n",
						rule.Path,
					)
				} else {
					fmt.Fprintf(os.Stderr,
						"cage: warning: read deny %q cannot be enforced on Linux "+
							"(Landlock is allowlist-only); use --strict for read protection\n",
						rule.Path,
					)
				}
			}
		}

		for _, rule := range config.WriteRules {
			if rule.Action == ActionDeny && rule.Mode&AccessRead != 0 {
				if rule.IsGlob {
					fmt.Fprintf(os.Stderr,
						"cage: warning: glob pattern %q cannot be enforced on Linux "+
							"(Landlock requires literal paths); pattern will be ignored\n",
						rule.Path,
					)
				} else {
					fmt.Fprintf(os.Stderr,
						"cage: warning: read deny %q cannot be enforced on Linux "+
							"(Landlock is allowlist-only); use --strict for read protection\n",
						rule.Path,
					)
				}
			}
		}
	}

	rules = append(rules, landlock.RWFiles("/dev/null"))

	// Build write deny set
	// Note: exceptions (carve-outs) only restore READ access, not write.
	// Use explicit 'allow:' paths to grant write access.
	writeDenySet := make(map[string]bool)
	for _, rule := range config.WriteRules {
		if rule.Action == ActionDeny && rule.Mode&AccessWrite != 0 && !rule.IsGlob {
			absPath, err := filepath.Abs(rule.Path)
			if err != nil {
				absPath = rule.Path
			}
			writeDenySet[absPath] = true
		}
	}

	// Helper to check if a path should be denied (is under a deny path)
	shouldDenyWrite := func(path string) bool {
		// Check if path matches a deny rule
		if writeDenySet[path] {
			return true
		}
		// Check if path is under a denied directory
		for denied := range writeDenySet {
			if strings.HasPrefix(path, denied+"/") {
				return true
			}
		}
		return false
	}

	for _, rule := range config.WriteRules {
		if rule.Action == ActionAllow {
			absPath, err := filepath.Abs(rule.Path)
			if err != nil {
				absPath = rule.Path
			}

			if shouldDenyWrite(absPath) {
				fmt.Fprintf(os.Stderr,
					"cage: info: skipping write allow for %s (matches deny rule)\n",
					rule.Path,
				)
				continue
			}

			info, err := os.Stat(absPath)
			if err != nil {
				continue
			}

			if info.IsDir() {
				if absPath == "/dev" || strings.HasPrefix(absPath, "/dev/") {
					rules = append(rules, landlock.RWDirs(absPath).WithIoctlDev())
					continue
				}
				rules = append(rules, landlock.RWDirs(absPath).WithRefer())
			} else {
				if strings.HasPrefix(absPath, "/dev/") {
					rules = append(rules, landlock.RWFiles(absPath).WithIoctlDev())
					continue
				}
				rules = append(rules, landlock.RWFiles(absPath))
			}
		}
	}

	err := landlock.V5.BestEffort().RestrictPaths(rules...)
	if err != nil {
		return fmt.Errorf("failed to apply Landlock restrictions: %w", err)
	}

	path, err := exec.LookPath(config.Command)
	if err != nil {
		return fmt.Errorf("command not found: %w", err)
	}

	argv := append([]string{config.Command}, config.Args...)
	err = syscall.Exec(path, argv, os.Environ())
	return fmt.Errorf("syscall.Exec failed: %w", err)
}
