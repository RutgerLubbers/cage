# Cage Quick Reference Card

A cross-platform security sandbox CLI that restricts file system access for untrusted commands.

## Installation

```bash
brew install --cask Warashi/tap/cage --no-quarantine  # macOS (Homebrew)
go install github.com/Warashi/cage@latest             # Go install
git clone https://github.com/Warashi/cage && cd cage && go build  # Source
```

## Basic Syntax

```bash
cage [flags] <command> [args...]
cage [flags] -- <command> [command-flags] [args...]
```

## Essential Flags

| Flag | Description |
|------|-------------|
| `--allow PATH` | Grant write access (repeatable) |
| `--allow-read PATH` | Grant read access (requires `--strict`) |
| `--strict` | Restrict reads to explicit paths only |
| `--deny PATH` | Deny read+write access |
| `--preset NAME` | Use a preset configuration |
| `--allow-keychain` | Allow macOS keychain access |
| `--allow-git` | Enable git operations in worktrees |
| `--allow-all` | Disable all restrictions (debugging only) |
| `--dry-run` | Show sandbox profile without executing |
| `--list-presets` | List available presets |
| `--no-defaults` | Skip default presets from config |

## Built-in Presets

Use with `--preset builtin:NAME`

| Preset | Description |
|--------|-------------|
| `secure` | **Recommended.** Strict + system reads + secrets deny + CWD write + git |
| `strict-base` | Minimal system read access, strict mode enabled |
| `secrets-deny` | Blocks SSH, AWS, cloud creds, GPG, shell history, browser data |
| `safe-home` | Strict + safe home dirs (Documents, Downloads, Projects) |
| `npm` | Node.js dev paths (., ~/.npm, ~/.cache/npm, node_modules) |
| `cargo` | Rust dev paths (., ~/.cargo, ~/.rustup, target) |

## Common Examples

```bash
# Recommended: secure defaults
cage --preset builtin:secure -- npm install

# Allow writing to current directory only
cage --allow . -- python script.py

# Protect secrets, allow CWD write
cage --preset builtin:secrets-deny --allow . -- ./build.sh

# AI coding assistant
cage --preset builtin:secure --allow-keychain -- claude

# Inspect sandbox profile (dry-run)
cage --dry-run --preset builtin:secure -- make

# Node.js development
cage --preset builtin:npm -- npm run build

# Rust development  
cage --preset builtin:cargo -- cargo build --release
```

## Configuration

**Config location:** `~/.config/cage/presets.yaml`

```yaml
defaults:
  presets: ["builtin:secure"]    # Apply to ALL commands

presets:
  my-preset:
    extends: ["builtin:strict-base"]
    allow: [".", "$HOME/.config/myapp"]
    strict: true
    allow-git: true

auto-presets:                    # Auto-apply by command name
  - command-pattern: ^(npm|yarn)$
    presets: [builtin:npm]
```

## Platform Differences

| Feature | Linux (Landlock) | macOS (sandbox-exec) |
|---------|------------------|----------------------|
| Kernel requirement | 5.13+ | Any modern version |
| Deny rules | Write only | Read + Write |
| Glob patterns | Not supported | Supported |
| Read protection | Strict mode only | Deny rules work |

**Linux users:** Use `--strict` mode for read protection. Deny rules only affect writes.

## Environment

`IN_CAGE=1` is set when running inside cage. Use in scripts:

```bash
if [ "$IN_CAGE" = "1" ]; then echo "Sandboxed"; fi
```

## Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| "Operation not permitted" | Add missing `--allow PATH` |
| Read denies not working (Linux) | Use `--strict` with `--allow-read` |
| Homebrew `/bin/ps` error | Add to ~/.zprofile: `if [[ -z $IN_CAGE ]]; then eval "$(/opt/homebrew/bin/brew shellenv)"; fi` |
| Symlink issues | Use `eval-symlinks: true` in preset config |

## More Information

- [Quickstart Guide](QUICKSTART.md)
- [Developer Guide](DEVELOPER_GUIDE.md)
- [GitHub Repository](https://github.com/Warashi/cage)
