# shellcheck shell=bash
# common.sh — shared helpers. Sourced by every snare command.

SNARE_HOME="${SNARE_HOME:-$HOME/.snare}"
SNARE_LOGS="$SNARE_HOME/logs"
SNARE_WORK="$SNARE_HOME/work"
SNARE_BACKUPS="$SNARE_HOME/backups"
SNARE_EVIDENCE="$SNARE_LOGS/evidence"
mkdir -p "$SNARE_LOGS" "$SNARE_WORK" "$SNARE_BACKUPS" "$SNARE_EVIDENCE"

# Repo root = parent of lib/
SNARE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOCS="${SNARE_IOCS:-$SNARE_ROOT/iocs.txt}"

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'
  C_BLD=$'\033[1m';  C_DIM=$'\033[2m';  C_OFF=$'\033[0m'
else
  C_RED=; C_GRN=; C_YLW=; C_BLD=; C_DIM=; C_OFF=
fi
red(){ printf '%s%s%s\n' "$C_RED" "$*" "$C_OFF"; }
grn(){ printf '%s%s%s\n' "$C_GRN" "$*" "$C_OFF"; }
ylw(){ printf '%s%s%s\n' "$C_YLW" "$*" "$C_OFF"; }
hdr(){ printf '\n%s== %s ==%s\n' "$C_BLD" "$*" "$C_OFF"; }
dim(){ printf '%s%s%s\n' "$C_DIM" "$*" "$C_OFF"; }

die(){ red "error: $*"; exit 1; }

# One ERE built from iocs.txt (comments and blanks stripped)
ioc_pattern(){
  [ -f "$IOCS" ] || die "IOC file not found: $IOCS"
  grep -v '^[[:space:]]*#' "$IOCS" | grep -v '^[[:space:]]*$' | paste -sd'|' -
}
ioc_list(){ grep -v '^[[:space:]]*#' "$IOCS" | grep -v '^[[:space:]]*$'; }

need(){ command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }

# Auth is ALWAYS the caller's own — snare never ships or stores a token.
require_gh(){
  need gh
  if ! gh auth status >/dev/null 2>&1; then
    red "Not authenticated to GitHub."
    echo "  Run:  gh auth login          (browser or paste your own token)"
    echo "  Or:   export GH_TOKEN=...    (scopes needed: repo, workflow)"
    exit 2
  fi
  gh auth setup-git >/dev/null 2>&1 || true   # no prompts on private clones
}

gh_user(){ gh api user --jq .login 2>/dev/null; }
