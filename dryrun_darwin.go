//go:build darwin

package main

import (
	"fmt"
	"strings"
)

func showDryRun(config *SandboxConfig) error {
	fmt.Println("Sandbox Profile (dry-run):")
	fmt.Println("========================================")
	fmt.Println("Version: macOS Sandbox v1")
	fmt.Println("Base profile: system.sb")
	fmt.Println()
	fmt.Println("Rules:")

	if config.AllowAll {
		fmt.Println("- Allow all operations (-allow-all flag)")
	} else {
		fmt.Println("- Allow all operations by default")
		fmt.Println("- Deny all file writes")
		fmt.Println("- Allow writes to:")
		fmt.Println("  * System temporary directories")

		if config.AllowKeychain {
			fmt.Println("  * Keychain directories (-allow-keychain)")
		}

		// Show write allow rules
		for _, rule := range config.WriteRules {
			if rule.Action == ActionAllow {
				fmt.Printf("  * %s (%s)\n", rule.Path, formatRuleSource(rule))
			}
		}

		if config.Strict {
			fmt.Println()
			fmt.Println("- STRICT MODE: Deny all file reads by default")
			fmt.Println("- Allow reads to:")

			for _, rule := range config.ReadRules {
				if rule.Action == ActionAllow {
					fmt.Printf("  * %s (%s)\n", rule.Path, formatRuleSource(rule))
				}
			}
		}

		// Show deny rules
		hasDenyRules := false
		for _, rule := range config.WriteRules {
			if rule.Action == ActionDeny {
				if !hasDenyRules {
					fmt.Println()
					fmt.Println("- Deny rules:")
					hasDenyRules = true
				}
				printDenyRule(rule)
			}
		}
		for _, rule := range config.ReadRules {
			if rule.Action == ActionDeny {
				if !hasDenyRules {
					fmt.Println()
					fmt.Println("- Deny rules:")
					hasDenyRules = true
				}
				printDenyRule(rule)
			}
		}
	}

	// Show conflicts if any
	if len(config.Conflicts) > 0 {
		fmt.Println()
		fmt.Println("Rule Conflicts:")
		fmt.Println("----------------------------------------")
		for _, conflict := range config.Conflicts {
			conflictType := "Cross-preset"
			if conflict.IsSamePreset {
				conflictType = "Intra-preset"
			}
			fmt.Printf("%s conflict for path: %s\n", conflictType, conflict.Path)
			fmt.Println("  Conflicting rules:")
			for _, rule := range conflict.Rules {
				actionStr := "allow"
				if rule.Action == ActionDeny {
					actionStr = "deny"
				}
				fmt.Printf("    - %s %s (%s) from %s\n", actionStr, rule.Path, formatAccessMode(rule.Mode), formatRuleSource(rule))
			}
			actionStr := "allow"
			if conflict.Resolution.Action == ActionDeny {
				actionStr = "deny"
			}
			fmt.Printf("  Resolution: %s from %s (CLI > preset, allow > deny, specific > general)\n", actionStr, formatRuleSource(conflict.Resolution))
			fmt.Println()
		}
	}

	fmt.Println()
	fmt.Println("Raw profile:")
	fmt.Println("----------------------------------------")

	profile, err := generateSandboxProfile(config)
	if err != nil {
		return fmt.Errorf("generate sandbox profile: %w", err)
	}
	fmt.Print(profile)
	fmt.Println("----------------------------------------")

	fmt.Println()
	fmt.Printf("Command: %s", config.Command)
	if len(config.Args) > 0 {
		fmt.Printf(" %s", strings.Join(config.Args, " "))
	}
	fmt.Println()

	return nil
}

func formatRuleSource(rule ResolvedRule) string {
	if rule.Source.IsCLI {
		return "CLI flag"
	}
	if rule.Source.PresetName != "" {
		return rule.Source.PresetName
	}
	return "preset"
}

func formatAccessMode(mode AccessMode) string {
	switch mode {
	case AccessRead:
		return "read"
	case AccessWrite:
		return "write"
	case AccessReadWrite:
		return "read+write"
	default:
		return "unknown"
	}
}

func printDenyRule(rule ResolvedRule) {
	globNote := ""
	if rule.IsGlob {
		globNote = " (glob pattern)"
	}
	fmt.Printf("  * %s (%s)%s - from %s\n", rule.Path, formatAccessMode(rule.Mode), globNote, formatRuleSource(rule))
	for _, exc := range rule.Except {
		fmt.Printf("    except: %s\n", exc)
	}
}
