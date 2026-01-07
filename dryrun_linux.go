//go:build linux

package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func showDryRun(config *SandboxConfig) error {
	fmt.Println("Sandbox Profile (dry-run):")
	fmt.Println("========================================")
	fmt.Println("Platform: Linux")
	fmt.Println("Technology: Landlock LSM")
	fmt.Println()
	fmt.Println("The following restrictions would be applied:")
	fmt.Println()
	fmt.Println("Rules:")

	if config.AllowAll {
		fmt.Println("- Allow all operations (-allow-all flag)")
	} else {
		if config.Strict {
			fmt.Println("- STRICT MODE: Only explicit read paths are allowed")
			fmt.Println("- Allow read access to:")

			for _, rule := range config.ReadRules {
				if rule.Action == ActionAllow {
					absPath, err := filepath.Abs(rule.Path)
					if err != nil {
						absPath = rule.Path
					}
					fmt.Printf("  * %s\n", absPath)
				}
			}
		} else {
			fmt.Println("- Allow read access to all files")
		}

		fmt.Println("- Deny write access except to:")
		fmt.Println("  * /dev/null (for discarding output)")

		for _, rule := range config.WriteRules {
			if rule.Action == ActionAllow {
				absPath, err := filepath.Abs(rule.Path)
				if err != nil {
					absPath = rule.Path
				}
				// Determine the source of the rule
				source := "user specified"
				if rule.Source.IsCLI {
					source = "command line"
				} else if rule.Source.PresetName != "" {
					source = rule.Source.PresetName
				}
				fmt.Printf("  * %s (%s)\n", absPath, source)
			}
		}

		// Collect all deny rules from both read and write rules
		denyRules := []ResolvedRule{}
		for _, rule := range config.ReadRules {
			if rule.Action == ActionDeny {
				denyRules = append(denyRules, rule)
			}
		}
		for _, rule := range config.WriteRules {
			if rule.Action == ActionDeny {
				denyRules = append(denyRules, rule)
			}
		}

		if len(denyRules) > 0 {
			fmt.Println()
			fmt.Println("- Deny rules:")
			for _, rule := range denyRules {
				modeStr := ""
				switch rule.Mode {
				case AccessRead:
					modeStr = "read"
				case AccessWrite:
					modeStr = "write"
				case AccessReadWrite:
					modeStr = "read+write"
				}
				absPath, err := filepath.Abs(rule.Path)
				if err != nil {
					absPath = rule.Path
				}
				note := ""
				if rule.Mode&AccessRead != 0 {
					if rule.IsGlob {
						note = " (WARNING: glob patterns not supported on Linux)"
					} else {
						note = " (WARNING: read deny only effective with --strict on Linux)"
					}
				}
				fmt.Printf("  * %s (%s)%s\n", absPath, modeStr, note)
			}
		}
	}

	fmt.Println()
	fmt.Printf("Command: %s", config.Command)
	if len(config.Args) > 0 {
		fmt.Printf(" %s", strings.Join(config.Args, " "))
	}
	fmt.Println()

	return nil
}
