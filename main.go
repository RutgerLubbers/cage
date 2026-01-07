package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
)

const inCageEnv = "IN_CAGE"

var version string

func Version() string {
	if version != "" {
		return version
	}

	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}

type flags struct {
	allowAll      bool
	allowKeychain bool
	allowGit      bool
	allowPaths    []string
	presets       []string
	listPresets   bool
	showPreset    string
	outputFormat  string
	configPath    string
	version       bool
	dryRun        bool
	strict        bool
	allowRead     []string
	deny          []string
	noDefaults    bool
}

func parseFlags() (*flags, []string) {
	f := &flags{}

	flag.BoolVar(
		&f.allowAll,
		"allow-all",
		false,
		"Disable all restrictions (use for testing/debugging only)",
	)

	flag.BoolVar(
		&f.allowKeychain,
		"allow-keychain",
		false,
		"Allow write access to the macOS keychain (only for macOS)",
	)

	flag.BoolVar(
		&f.allowGit,
		"allow-git",
		false,
		"Allow access to git common directory (enables git operations in worktrees)",
	)

	flag.BoolVar(
		&f.strict,
		"strict",
		false,
		"Enable strict mode: do not allow read access to / by default",
	)

	// Custom flag parsing to handle multiple --allow flags
	var allowFlags arrayFlags
	flag.Var(
		&allowFlags,
		"allow",
		"Grant write access to specific paths (can be used multiple times)",
	)

	// Custom flag parsing to handle multiple --allow-read flags
	var allowReadFlags arrayFlags
	flag.Var(
		&allowReadFlags,
		"allow-read",
		"Grant read access to specific paths (only used with --strict)",
	)

	// Custom flag parsing to handle multiple --deny flags
	var denyFlags arrayFlags
	flag.Var(
		&denyFlags,
		"deny",
		"Deny read and write access to paths; use 'except' in presets for read-only carve-outs",
	)

	// Custom flag parsing to handle multiple --preset flags
	var presetFlags arrayFlags
	flag.Var(
		&presetFlags,
		"preset",
		"Use a predefined preset configuration (can be used multiple times)",
	)

	flag.BoolVar(
		&f.listPresets,
		"list-presets",
		false,
		"List available presets",
	)

	flag.StringVar(
		&f.showPreset,
		"show-preset",
		"",
		"Show the contents of a preset",
	)

	flag.StringVar(
		&f.outputFormat,
		"o",
		"text",
		"Output format for --show-preset: text, yaml (resolved), or raw (unresolved YAML)",
	)

	flag.StringVar(
		&f.configPath,
		"config",
		"",
		"Path to custom configuration file",
	)

	flag.BoolVar(
		&f.version,
		"version",
		false,
		"Print version information and exit",
	)

	flag.BoolVar(
		&f.dryRun,
		"dry-run",
		false,
		"Show the generated sandbox profile without executing",
	)

	flag.BoolVar(
		&f.noDefaults,
		"no-defaults",
		false,
		"Skip default presets defined in config",
	)

	flag.Parse()

	f.allowPaths = []string(allowFlags)
	f.presets = []string(presetFlags)
	f.allowRead = []string(allowReadFlags)
	f.deny = []string(denyFlags)

	return f, flag.Args()
}

// arrayFlags is a custom flag type that accumulates values
type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, ", ")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func printPreset(name string, p *Preset, format string, extends []string) {
	if format == "yaml" {
		printPresetYAML(name, p, extends)
		return
	}
	printPresetText(name, p, extends)
}

func sortedPaths(paths []AllowPath) []AllowPath {
	// Deduplicate by path, keeping first occurrence
	seen := make(map[string]bool)
	unique := make([]AllowPath, 0, len(paths))
	for _, p := range paths {
		if !seen[p.Path] {
			seen[p.Path] = true
			unique = append(unique, p)
		}
	}
	// Sort by path
	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Path < unique[j].Path
	})
	return unique
}

func printPresetText(name string, p *Preset, extends []string) {
	fmt.Printf("Preset: %s\n", name)
	fmt.Println("========================================")

	if len(extends) > 0 {
		fmt.Printf("Extends: %s\n", strings.Join(extends, " → "))
		fmt.Println()
	}

	if len(p.Extends) > 0 {
		fmt.Println("extends:")
		for _, ext := range p.Extends {
			fmt.Printf("  - %s\n", ext)
		}
	}

	if p.AllowGit {
		fmt.Println("allow-git: true")
	}
	if p.AllowKeychain {
		fmt.Println("allow-keychain: true")
	}
	if p.SkipDefaults {
		fmt.Println("skip-defaults: true")
	}
	if p.Strict {
		fmt.Println("strict: true")
	}

	if len(p.Allow) > 0 {
		fmt.Println("\nallow (write paths):")
		for _, path := range sortedPaths(p.Allow) {
			fmt.Printf("  - %s\n", path.Path)
		}
	}

	if len(p.Read) > 0 {
		fmt.Println("\nread (read-only paths):")
		for _, path := range sortedPaths(p.Read) {
			fmt.Printf("  - %s\n", path.Path)
		}
	}

	if len(p.Deny) > 0 {
		fmt.Println("\ndeny (read+write, except restores read-only):")
		for _, path := range sortedPaths(p.Deny) {
			fmt.Printf("  - %s\n", path.Path)
			for _, exc := range path.Except {
				fmt.Printf("    except: %s\n", exc)
			}
		}
	}
}

func printPresetYAML(name string, p *Preset, extends []string) {
	presetName := name
	if strings.HasPrefix(name, "builtin:") {
		presetName = strings.TrimPrefix(name, "builtin:")
	}

	if len(extends) > 0 {
		fmt.Printf("# Extends: %s\n", strings.Join(extends, " → "))
	}
	fmt.Println("presets:")
	fmt.Printf("  %s:\n", presetName)

	if len(p.Extends) > 0 {
		fmt.Println("    extends:")
		for _, ext := range p.Extends {
			fmt.Printf("      - %q\n", ext)
		}
	}

	if p.AllowGit {
		fmt.Println("    allow-git: true")
	}
	if p.AllowKeychain {
		fmt.Println("    allow-keychain: true")
	}
	if p.SkipDefaults {
		fmt.Println("    skip-defaults: true")
	}
	if p.Strict {
		fmt.Println("    strict: true")
	}

	if len(p.Allow) > 0 {
		fmt.Println("    allow:")
		for _, path := range sortedPaths(p.Allow) {
			fmt.Printf("      - %q\n", path.Path)
		}
	}

	if len(p.Read) > 0 {
		fmt.Println("    read:")
		for _, path := range sortedPaths(p.Read) {
			fmt.Printf("      - %q\n", path.Path)
		}
	}

	if len(p.Deny) > 0 {
		fmt.Println("    deny:")
		for _, path := range sortedPaths(p.Deny) {
			fmt.Printf("      - %q\n", path.Path)
		}
	}
}

func main() {
	// Indicate that we are running inside a cage
	if err := os.Setenv(inCageEnv, "1"); err != nil {
		fmt.Fprintf(os.Stderr, "cage: error setting environment variable %s: %v\n", inCageEnv, err)
		os.Exit(1)
	}

	flags, args := parseFlags()

	// Handle version flag
	if flags.version {
		fmt.Printf("cage version %s\n", Version())
		os.Exit(0)
	}

	// Load configuration
	config, err := loadConfig(flags.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cage: error loading config: %v\n", err)
		os.Exit(1)
	}

	// Handle list-presets flag
	if flags.listPresets {
		presets := config.ListPresets()
		if len(presets) == 0 {
			fmt.Println("No presets available")
		} else {
			fmt.Println("Available presets:")
			for _, name := range presets {
				fmt.Printf("  - %s\n", name)
			}
		}
		os.Exit(0)
	}

	// Handle show-preset flag
	if flags.showPreset != "" {
		rawPreset, ok := config.GetPreset(flags.showPreset)
		if !ok {
			fmt.Fprintf(os.Stderr, "cage: preset not found: %s\n", flags.showPreset)
			os.Exit(1)
		}

		if flags.outputFormat == "raw" {
			printPreset(flags.showPreset, &rawPreset, "yaml", nil)
		} else {
			resolved, err := config.ResolvePreset(flags.showPreset, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cage: %v\n", err)
				os.Exit(1)
			}
			printPreset(flags.showPreset, resolved, flags.outputFormat, rawPreset.Extends)
		}
		os.Exit(0)
	}

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: cage [flags] <command> [command-args...]\n")
		fmt.Fprintf(
			os.Stderr,
			"       cage [flags] -- <command> [command-flags] [command-args...]\n",
		)
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Auto-detect presets and merge with command-line presets
	if len(config.AutoPresets) > 0 {
		autoPresets, err := config.GetAutoPresets(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "cage: error detecting auto-presets: %v\n", err)
			os.Exit(1)
		}

		// Merge auto-detected presets with command-line presets
		// Command-line presets come first to maintain priority
		flags.presets = append(flags.presets, autoPresets...)
	}

	// Determine if we should skip defaults
	skipDefaults := flags.noDefaults

	// Check if any preset has skip-defaults: true
	if !skipDefaults {
		for _, presetName := range flags.presets {
			resolved, err := config.ResolvePreset(presetName, nil)
			if err != nil {
				// Will be reported later during processing
				continue
			}
			if resolved.SkipDefaults {
				skipDefaults = true
				break
			}
		}
	}

	// Apply default presets (prepend to preset list so they're processed first)
	if !skipDefaults && len(config.Defaults.Presets) > 0 {
		flags.presets = append(config.Defaults.Presets, flags.presets...)
	}

	// Merge preset paths with command-line paths
	allowedPaths := flags.allowPaths
	allowKeychain := flags.allowKeychain
	allowGit := flags.allowGit
	strict := flags.strict
	readPaths := flags.allowRead
	var denyRules []DenyRule

	// Add deny rules from command-line flags
	for _, path := range flags.deny {
		denyRules = append(denyRules, DenyRule{
			Pattern: os.ExpandEnv(path),
			Modes:   AccessReadWrite,
			IsGlob:  strings.Contains(path, "*"),
		})
	}

	// Process each preset and merge their settings
	for _, presetName := range flags.presets {
		resolved, err := config.ResolvePreset(presetName, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cage: %v\n", err)
			os.Exit(1)
		}

		// Process preset to expand dynamic values
		processedPreset, err := resolved.ProcessPreset()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cage: error processing preset '%s': %v\n", presetName, err)
			os.Exit(1)
		}

		// Add preset paths
		for _, path := range processedPreset.Allow {
			allowedPaths = append(allowedPaths, path.Path)
		}

		// Add preset read paths
		for _, path := range processedPreset.Read {
			readPaths = append(readPaths, path.Path)
		}

		// Add preset deny rules
		for _, path := range processedPreset.Deny {
			denyRules = append(denyRules, DenyRule{
				Pattern: path.Path,
				Modes:   AccessReadWrite,
				IsGlob:  strings.Contains(path.Path, "*"),
				Except:  path.Except,
			})
		}

		// Preset's settings are ORed with command-line flags
		allowKeychain = allowKeychain || processedPreset.AllowKeychain
		allowGit = allowGit || processedPreset.AllowGit
		strict = strict || processedPreset.Strict
	}

	// Create sandbox configuration
	sandboxConfig := &SandboxConfig{
		AllowAll:      flags.allowAll,
		AllowKeychain: allowKeychain,
		AllowGit:      allowGit,
		AllowedPaths:  allowedPaths,
		Strict:        strict,
		ReadPaths:     readPaths,
		DenyRules:     denyRules,
		Command:       args[0],
		Args:          args[1:],
	}

	// Handle dry-run flag
	if flags.dryRun {
		printDryRunAndExit(sandboxConfig)
	}

	// Execute in sandbox
	if err := RunInSandbox(sandboxConfig); err != nil {
		fmt.Fprintf(os.Stderr, "cage: %v\n", err)
		os.Exit(1)
	}
}
