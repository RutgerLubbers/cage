#!/bin/bash
# File: test_e2e_dryrun.sh
# Layer 4: End-to-End Dry Run Test

echo "=== Testing End-to-End Dry Run ==="

# Build cage first
if ! go build -o cage .; then
    echo "❌ Failed to build cage"
    exit 1
fi

# Test 1: Basic dry-run with deny rule (the fix target)
echo "Test 1: Dry run with deny rule in strict mode..."
OUTPUT=$(HOME=/tmp ./cage --dry-run --no-defaults --strict --deny "/Users/test" -- echo hello 2>&1)

if [ $? -ne 0 ]; then
    echo "❌ cage --dry-run failed"
    echo "$OUTPUT"
    exit 1
fi

# Count occurrences of the deny rule in the display section (should be 1, not 2)
DISPLAY_COUNT=$(echo "$OUTPUT" | grep -c "^\s*\* /Users/test (read+write) - from CLI flag")
if [ "$DISPLAY_COUNT" -ne 1 ]; then
    echo "❌ Expected deny rule to appear once in display, got $DISPLAY_COUNT times"
    echo "$OUTPUT"
    exit 1
fi

# Count occurrences in raw profile (should be 2: one write deny, one read deny)
WRITE_DENY_COUNT=$(echo "$OUTPUT" | grep -c "(deny file-write\* (subpath \"/Users/test\"))")
READ_DENY_COUNT=$(echo "$OUTPUT" | grep -c "(deny file-read-data (subpath \"/Users/test\"))")

if [ "$WRITE_DENY_COUNT" -ne 1 ]; then
    echo "❌ Expected write deny to appear once, got $WRITE_DENY_COUNT times"
    exit 1
fi

if [ "$READ_DENY_COUNT" -ne 1 ]; then
    echo "❌ Expected read deny to appear once, got $READ_DENY_COUNT times"
    exit 1
fi

echo "✅ All dry-run tests passed!"
echo "  - Display shows deny rule once (no duplicates)"
echo "  - Raw profile has correct write and read deny rules"