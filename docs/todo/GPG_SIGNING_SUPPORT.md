# Task: GPG Signing Support in Cage

**Status:** Todo  
**Priority:** Medium  
**Type:** Feature Enhancement

## Problem Statement

When running inside a cage sandbox with `builtin:secure`, GPG commit signing fails because `~/.gnupg` is blocked:

```
gpg: keyblock resource '/Users/user/.gnupg/pubring.kbx': Permission denied
gpg: signing failed: No secret key
```

This is by design - the sandbox protects sensitive GPG keys. However, users who want to sign commits need a safe way to do so.

## Goals

1. Allow GPG signing without exposing private keys directly
2. Document how to configure GPG agent for use with cage
3. Provide cross-platform instructions (macOS + Linux)
4. Add optional preset for GPG signing

## Proposed Solution

### Approach: GPG Agent Socket Access

GPG agent handles private key operations. The sandbox only needs access to:
- Agent socket (for communication)
- Public keyring (to identify keys)
- Trust database (for key validation)

Private keys (`~/.gnupg/private-keys-v1.d/`) remain inaccessible.

### Implementation Tasks

#### 1. Create `gpg-signing` example preset

```yaml
# examples/presets.yaml
gpg-signing:
  allow:
    # GPG agent sockets (need write for bidirectional communication)
    - "$HOME/.gnupg/S.gpg-agent"
    - "$HOME/.gnupg/S.gpg-agent.extra"
    - "$HOME/.gnupg/S.keyboxd"
  read:
    # Public key data (read-only sufficient)
    - "$HOME/.gnupg/pubring.kbx"
    - "$HOME/.gnupg/trustdb.gpg"
    - "$HOME/.gnupg/tofu.db"
```

**Note:** This needs testing to determine minimal required access.

#### 2. Document GPG Agent Setup

Add to `docs/GPG_SIGNING.md`:

##### macOS Setup

```bash
# Install GPG (if not installed)
brew install gnupg

# Start agent manually
gpgconf --launch gpg-agent

# Auto-start on login - add to ~/.zprofile or ~/.bash_profile:
if [ -z "$GPG_AGENT_INFO" ]; then
  gpgconf --launch gpg-agent
  export GPG_TTY=$(tty)
fi

# Or use launchd (recommended for macOS):
# Create ~/Library/LaunchAgents/org.gnupg.gpg-agent.plist
```

**launchd plist file:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.gnupg.gpg-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/gpgconf</string>
        <string>--launch</string>
        <string>gpg-agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

Load with: `launchctl load ~/Library/LaunchAgents/org.gnupg.gpg-agent.plist`

##### Linux Setup

```bash
# Install GPG (Debian/Ubuntu)
sudo apt install gnupg

# Install GPG (Fedora/RHEL)
sudo dnf install gnupg2

# Start agent manually
gpgconf --launch gpg-agent

# Auto-start on login - add to ~/.bashrc or ~/.profile:
export GPG_TTY=$(tty)
gpgconf --launch gpg-agent

# Or use systemd user service (recommended):
systemctl --user enable gpg-agent.socket
systemctl --user start gpg-agent.socket
```

**systemd socket activation** (usually pre-configured):
```bash
# Check if socket unit exists
systemctl --user status gpg-agent.socket

# Enable socket activation (starts agent on demand)
systemctl --user enable gpg-agent.socket

# The socket files are typically at:
# $XDG_RUNTIME_DIR/gnupg/S.gpg-agent
# or ~/.gnupg/S.gpg-agent
```

##### Verify Agent is Running

```bash
# Check agent status
gpg-connect-agent /bye && echo "Agent running"

# List cached keys
gpg-connect-agent 'keyinfo --list' /bye

# Check socket location
gpgconf --list-dirs agent-socket
```

#### 3. Document Usage with Cage

```bash
# Option 1: Use gpg-signing preset (when available)
cage --preset builtin:secure --preset gpg-signing -- git commit -S -m "message"

# Option 2: Extend in your config
# ~/.config/cage/presets.yaml
presets:
  my-dev:
    extends:
      - "builtin:secure"
    allow:
      - "$HOME/.gnupg"  # Full GPG access
```

#### 4. Alternative: SSH Signing

Document SSH signing as a simpler alternative (Git 2.34+):

```bash
# Configure git to use SSH for signing
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub

# SSH agent is typically already accessible or easier to configure
```

## Research Needed

1. **Minimal permissions**: Test exact files/sockets needed for signing
2. **Socket locations**: Verify paths on different distros/versions
3. **Keyboxd**: Newer GPG versions use keyboxd - verify socket requirements
4. **Pinentry**: Does pinentry work through the sandbox? May need `allow-tty` or similar

## Security Considerations

- **Read-only pubring**: Sufficient for identifying signing key
- **Socket access**: Required for agent communication, but agent protects private key
- **Private keys**: Should NEVER be directly accessible from sandbox
- **Passphrase caching**: Agent caches passphrase, so user enters it once outside cage

## Testing Checklist

- [ ] GPG signing works with minimal preset on macOS
- [ ] GPG signing works with minimal preset on Linux (systemd)
- [ ] GPG signing works with minimal preset on Linux (non-systemd)
- [ ] Agent auto-start works on macOS (launchd)
- [ ] Agent auto-start works on Linux (systemd)
- [ ] Pinentry prompts work correctly
- [ ] Private keys remain inaccessible

## Related

- SSH signing as alternative (#future)
- `allow-gpg` flag similar to `allow-keychain` (#future)
