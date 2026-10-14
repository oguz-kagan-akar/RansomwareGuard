#!/usr/bin/env bash
set -Eeuo pipefail

# Usage:
#   ./push.sh [remote-url]
#   ./push.sh --watch [remote-url]
#
# First use:
#   ./push.sh https://github.com/USERNAME/RansomwareGuard.git
#
# Watch mode requires inotifywait (Debian/Kali: sudo apt install inotify-tools).

WATCH=0
REMOTE_URL=""

if [[ "${1:-}" == "--watch" ]]; then
  WATCH=1
  shift
fi
REMOTE_URL="${1:-}"

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is not installed." >&2
  exit 1
fi

if [[ ! -d .git ]]; then
  git init
fi

# Keep the default branch name consistent with GitHub.
current_branch="$(git branch --show-current || true)"
if [[ -z "$current_branch" ]]; then
  git checkout -b main
elif [[ "$current_branch" != "main" && "$(git rev-parse --verify HEAD 2>/dev/null || true)" == "" ]]; then
  git branch -M main
fi

if [[ -n "$REMOTE_URL" ]]; then
  if git remote get-url origin >/dev/null 2>&1; then
    git remote set-url origin "$REMOTE_URL"
  else
    git remote add origin "$REMOTE_URL"
  fi
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "Error: no 'origin' remote is configured." >&2
  echo "Run: ./push.sh https://github.com/USERNAME/RansomwareGuard.git" >&2
  exit 1
fi

push_once() {
  # Stage repository changes; .gitignore excludes common local/secret files.
  git add -A

  if git diff --cached --quiet; then
    echo "No changes to commit."
  else
    commit_message="Update RansomwareGuard: $(date '+%Y-%m-%d %H:%M:%S')"
    git commit -m "$commit_message"
  fi

  branch="$(git branch --show-current)"
  if [[ -z "$branch" ]]; then
    git checkout -b main
    branch="main"
  fi

  # -u records the upstream on the first push.
  git push -u origin "$branch"
}

if (( WATCH == 0 )); then
  push_once
  exit 0
fi

if ! command -v inotifywait >/dev/null 2>&1; then
  echo "Error: watch mode requires inotifywait." >&2
  echo "Install it with: sudo apt install inotify-tools" >&2
  exit 1
fi

echo "Watching for file changes. Press Ctrl+C to stop."
while true; do
  # Wait for a change, then debounce rapid edits before committing.
  inotifywait -r -e close_write,create,delete,move \
    --exclude '(^|/)\.git(/|$)|(^|/)(ransomguard\.log|.*\.tmp)$' . >/dev/null
  sleep 2
  while inotifywait -r -t 1 -e close_write,create,delete,move \
    --exclude '(^|/)\.git(/|$)|(^|/)(ransomguard\.log|.*\.tmp)$' . >/dev/null 2>&1; do
    sleep 2
  done
  push_once || echo "Push failed; fix the issue and make another change or run ./push.sh manually."
done
