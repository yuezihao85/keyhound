#!/usr/bin/env sh
# Minimal pre-commit hook, no framework required.
#
# Install (adjust the absolute path to your keyhound checkout):
#   cp examples/scan-diff.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#   git config keyhound.cli "python /abs/path/to/keyhound/keyhound-cli.py"
#
# The diff is streamed straight into keyhound via stdin: nothing is written to
# disk, so a staged credential never leaves the pipe.
set -eu

# Resolve the CLI in this order: env var > git config > sibling checkout.
CLI="${KEYHOUND_CLI:-}"
if [ -z "$CLI" ]; then
  CLI="$(git config --get keyhound.cli 2>/dev/null || true)"
fi
if [ -z "$CLI" ]; then
  CLI="python $(dirname "$0")/../../keyhound-cli.py"
fi

if git diff --cached --quiet; then
  exit 0
fi

git diff --cached --no-ext-diff --unified=0 | $CLI --no-baseline --color never -
status=$?

if [ "$status" -eq 1 ]; then
  echo "" >&2
  echo "keyhound: secret detected in staged diff, commit aborted." >&2
  echo "Rotate the credential, or add 'keyhound:allow' on the line to suppress." >&2
  exit 1
fi

exit "$status"
