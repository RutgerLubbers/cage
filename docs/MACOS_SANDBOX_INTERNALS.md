# macOS Sandbox Internals

This document explains the macOS sandbox-exec implementation details in cage, particularly the distinction between different file operation types.

## Sandbox Operations Overview

macOS sandbox-exec (SBPL - Sandbox Profile Language) provides fine-grained control over file operations. The key insight is that `file-read*` is a **wildcard** that matches multiple distinct operations:

| Operation | Description | Syscalls |
|-----------|-------------|----------|
| `file-read-data` | Read file contents | `read()`, `pread()` |
| `file-read-metadata` | Read file metadata | `stat()`, `lstat()`, `fstat()` |
| `file-read-xattr` | Read extended attributes | `getxattr()` |
| `file-read*` | **All of the above** | All read operations |

Similarly for writes:
| Operation | Description | Syscalls |
|-----------|-------------|----------|
| `file-write-data` | Write file contents | `write()`, `pwrite()` |
| `file-write-create` | Create new files | `open()` with O_CREAT |
| `file-write-unlink` | Delete files | `unlink()` |
| `file-write*` | **All of the above** | All write operations |

## Why We Use `file-read-data` Instead of `file-read*`

### The Problem

When using `(deny file-read* (subpath "/Users/example"))`, we block **all** read operations including `stat()` and `lstat()`. This causes issues with tools like Node.js/npm that need to:

1. Resolve symlinks during module loading
2. Check if paths exist before accessing them
3. Traverse parent directories during path resolution

For example, when npm tries to run, it calls `lstat()` on parent directories like `/Users` to resolve paths - even if it doesn't need to read any files there.

### The Solution

Use `(deny file-read-data ...)` instead of `(deny file-read* ...)`. This:

- ✅ **Allows** `stat()` / `lstat()` (file metadata) - needed for path resolution
- ❌ **Blocks** `read()` (file contents) - protects sensitive data
- ❌ **Blocks** `readdir()` (directory listing) - can't enumerate files

### Security Model Comparison

| Operation | `file-read*` deny | `file-read-data` deny |
|-----------|-------------------|----------------------|
| `stat /path` | ❌ Blocked | ✅ Allowed |
| `lstat /path` | ❌ Blocked | ✅ Allowed |
| `ls /path` (readdir) | ❌ Blocked | ❌ Blocked |
| `cat /path` (read) | ❌ Blocked | ❌ Blocked |

This is the ideal security model: tools can resolve paths (needed for startup), but cannot read file contents or list directory contents.

## Strict Mode Considerations

In strict mode, we use a global `(deny file-read-data)` instead of `(deny file-read*)`. This requires one additional rule:

```scheme
(allow file-read-data (literal "/"))
```

This allows processes to read the root directory, which is necessary for:
- Process startup and initialization
- dylib loading from system paths
- Path resolution beginning from root

Without this rule, many processes will crash with SIGABRT (exit code 134) during startup.

## Testing the Behavior

You can verify the behavior with these commands:

```bash
# Create a test sandbox profile
cat << 'EOF' > /tmp/test.sb
(version 1)
(import "system.sb")
(allow default)
(deny file-read-data (subpath "/Users/yourname"))
(allow file-read-data (subpath "/Users/yourname/project"))
EOF

# Test metadata access (should work)
sandbox-exec -f /tmp/test.sb stat /Users/yourname/.bashrc

# Test content read (should fail)
sandbox-exec -f /tmp/test.sb cat /Users/yourname/.bashrc

# Test directory listing (should fail)
sandbox-exec -f /tmp/test.sb ls /Users/yourname

# Test allowed path (should work)
sandbox-exec -f /tmp/test.sb cat /Users/yourname/project/README.md
```

## Implementation in Cage

### Non-Strict Mode (Default)

When using `--deny /path`, cage generates:
```scheme
(deny file-write* (subpath "/path"))
(deny file-read-data (subpath "/path"))
```

### Strict Mode

When using `--strict`, cage generates:
```scheme
(deny file-read-data)
(allow file-read-data (literal "/"))
(allow file-read-data (subpath "/allowed/path"))
; ... more allow rules
```

### Carve-outs (Exceptions)

Deny rules can have exceptions that restore read access:
```yaml
presets:
  my-preset:
    deny:
      - path: $HOME
        except:
          - $HOME/.config/myapp
```

This generates:
```scheme
(deny file-read-data (subpath "/Users/example"))
(allow file-read-data (subpath "/Users/example/.config/myapp"))
```

## References

- Apple Sandbox Documentation (limited public docs)
- `/System/Library/Sandbox/Profiles/system.sb` - System sandbox profile
- `/System/Library/Sandbox/Profiles/application.sb` - Application sandbox template
- `sandbox-exec(1)` man page

## Troubleshooting

### Process crashes with exit code 134 (SIGABRT)

This usually means the sandbox is blocking a required operation. Common causes:

1. **Strict mode without root literal**: Add `(allow file-read-data (literal "/"))`
2. **Missing allow for binary location**: Ensure the binary's directory is readable
3. **Missing allow for dylib paths**: System libraries need to be accessible

### "Operation not permitted" errors

Check which operation is being denied:
- If `stat` fails → you're using `file-read*` instead of `file-read-data`
- If `cat` fails → working as intended (content read blocked)
- If `ls` fails → working as intended (directory listing blocked)

### npm/node fails with lstat error

Ensure you're using `file-read-data` for deny rules, not `file-read*`. Node.js needs to call `lstat()` on parent directories during module resolution.
