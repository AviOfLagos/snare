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

# Section 1 greps the whole working tree, node_modules included, because that
# is where npm-delivered malware lands. Doing that with one ~50-branch ERE was
# pathological: the `.*` branches backtrack across minified bundles, and a
# real Next.js checkout took over 22 minutes without finishing. (It used to
# appear fast only because `| head -40` killed grep early once false positives
# filled the buffer — fixing those made the real cost visible.)
#
# Most IOCs are plain strings. grep -F matches those with Aho-Corasick, in one
# pass, regardless of how many there are. Only the genuinely regex ones need
# -E. A line whose sole metacharacter is an escaped dot is a literal once the
# backslash is dropped.
# A pattern is a literal if every metacharacter in it is backslash-escaped:
# `global\['_t_s'\]` and `setup_bun\.js` are plain strings once unescaped,
# even though they look like regexes. Only patterns with a LIVE metacharacter
# -- `.*`, `?`, `|`, a character class -- actually need the -E engine, and
# those are the ones that backtrack across minified bundles.
_ioc_split(){
  ioc_list | snare_py -c '
import re, sys
META = set("[](){}*+?|^$.")
want_literals = sys.argv[1] == "lit"
for line in sys.stdin.read().splitlines():
    if not line:
        continue
    bare = re.sub(r"\\.", "", line)          # drop escaped pairs
    is_literal = not any(c in META for c in bare)
    if is_literal == want_literals:
        print(re.sub(r"\\(.)", r"\1", line) if is_literal else line)
' "$1"
}
ioc_literals(){ _ioc_split lit; }
ioc_regexes(){  _ioc_split re | paste -sd"|" -; }

# Scanning a working tree means scanning node_modules, because that is where
# npm-delivered malware lands. On macOS, BSD grep -rIn across a real
# node_modules (53,740 files / 976MB, measured on one Next.js checkout) takes
# over two minutes for a single pass. ripgrep does the same pass in 1.6s, so
# snare uses it when it is present and falls back to grep when it is not.
#
# The literal pass is engine-independent by definition. The regex pass is not:
# ripgrep uses the Rust engine rather than POSIX ERE. The 11 regex IOCs use
# only POSIX classes, `.*`, `?`, `|` and simple classes, all of which both
# engines read the same way, and the selftest asserts detection against the
# real samples under whichever engine is in use.
snare_has_rg(){ command -v rg >/dev/null 2>&1; }

# $1 = mode (lit|re), $2 = literals file or regex, rest = extra args
snare_grep_tree(){
  local mode="$1" pat="$2"; shift 2
  if snare_has_rg; then
    case "$mode" in
      lit) rg -n --no-ignore --hidden -g '!.git' -F -f "$pat" "$@" . 2>/dev/null ;;
      re)  rg -n --no-ignore --hidden -g '!.git' -e "$pat"    "$@" . 2>/dev/null ;;
    esac
    return 0
  fi
  case "$mode" in
    lit) grep -rInF -f "$pat" . --exclude-dir=.git "$@" 2>/dev/null ;;
    re)  grep -rInE "$pat"    . --exclude-dir=.git "$@" 2>/dev/null ;;
  esac
}

need(){ command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }

# Auth is ALWAYS the caller's own — snare never ships or stores a token.
require_gh(){
  # gh missing entirely: say how to get it for this platform rather than
  # printing a bare "need gh".
  if ! command -v gh >/dev/null 2>&1; then
    red "The GitHub CLI (gh) is not installed."
    case "$SNARE_OS" in
      macos)     echo "  brew install gh" ;;
      linux|wsl) echo "  Debian/Ubuntu: see https://github.com/cli/cli/blob/trunk/docs/install_linux.md"
                 echo "  Fedora:        sudo dnf install gh"
                 echo "  Arch:          sudo pacman -S github-cli" ;;
      windows)   echo "  winget install GitHub.cli    (then reopen Git Bash)" ;;
      *)         echo "  https://cli.github.com" ;;
    esac
    exit 2
  fi
  if ! gh auth status >/dev/null 2>&1; then
    red "Not authenticated to GitHub."
    # Offer to do it now rather than making them look up the command. Only
    # when a human is present: never hijack a script, a hook or a timer.
    if [ -t 0 ] && [ -t 1 ] && [ -z "${CI:-}" ]; then
      echo "  snare uses YOUR credentials — it ships no token of its own."
      printf '  Run "gh auth login" now? [Y/n] '
      local _ans; read -r _ans
      case "$_ans" in
        ""|y|Y|yes|YES)
          gh auth login || { red "  authentication did not complete"; exit 2; }
          gh auth status >/dev/null 2>&1 || { red "  still not authenticated"; exit 2; }
          grn "  authenticated as $(gh api user --jq .login 2>/dev/null)" ;;
        *)
          echo "  Run:  gh auth login          (browser or paste your own token)"
          echo "  Or:   export GH_TOKEN=...    (scopes needed: repo, workflow)"
          exit 2 ;;
      esac
    else
      echo "  Run:  gh auth login          (browser or paste your own token)"
      echo "  Or:   export GH_TOKEN=...    (scopes needed: repo, workflow)"
      exit 2
    fi
  fi
  gh auth setup-git >/dev/null 2>&1 || true   # no prompts on private clones
}

# `grep -q` exits on the first match, which sends SIGPIPE to whatever is still
# writing into the pipe. bin/snare runs under `set -o pipefail`, so that 141
# becomes the pipeline's status and `producer | grep -q X` reports NO MATCH
# even though X was there. It is silent and size-dependent: it only bites once
# the producer has more to write than the pipe buffer holds, so it passed every
# small fixture and failed on real repos.
#
# Measured: a file tree of 20k paths with .vscode/tasks.json first was reported
# clean by `scan github`. Reading to EOF costs nothing here and cannot misfire.
_qmatch(){ grep "$@" >/dev/null; }

# Python 3 under whatever name this platform gives it: Debian/Ubuntu and macOS
# expose python3, Git Bash on Windows often only has the py launcher.
snare_py(){
  if   command -v python3 >/dev/null 2>&1; then python3 "$@"
  elif command -v python  >/dev/null 2>&1; then python  "$@"
  elif command -v py      >/dev/null 2>&1; then py -3   "$@"
  else die "Python 3 is required but not installed"; fi
}


# --- portable primitives ---------------------------------------------------
# First four bytes of a file as lowercase hex, e.g. "774f4632" (wOF2).
# xxd ships with vim and is absent on minimal Linux images and some Git Bash
# installs; od is POSIX and always present. Without this, a missing xxd made
# every genuine font look like a payload — and in the pre-push hook that
# blocked every push from any repo containing fonts.
magic4(){ head -c 4 "$1" 2>/dev/null | od -An -v -tx1 2>/dev/null | tr -d ' \n'; }

# Is this a real font? 0 = yes or undeterminable, 1 = definitely not.
# "Undeterminable" deliberately counts as fine: refusing to guess beats
# accusing a user's assets because a tool was missing.
is_font(){
  local m; m="$(magic4 "$1")"
  [ -z "$m" ] && return 0
  case "$m" in
    774f4632|774f4646|00010000|4f54544f|74727565) return 0 ;;
    *) return 1 ;;
  esac
}

# Short stable hash. shasum is perl-based and not everywhere; fall back through
# the common alternatives, then to cksum, which is POSIX.
short_hash(){
  if command -v shasum   >/dev/null 2>&1; then shasum   | cut -c1-16
  elif command -v sha1sum >/dev/null 2>&1; then sha1sum  | cut -c1-16
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-16
  elif command -v md5sum  >/dev/null 2>&1; then md5sum   | cut -c1-16
  else cksum | tr -d ' ' | cut -c1-16
  fi
}

gh_user(){ gh api user --jq .login 2>/dev/null; }

# ---------------------------------------------------------------- platform
snare_os(){
  case "$(uname -s 2>/dev/null)" in
    Darwin) echo macos ;;
    Linux)  grep -qi microsoft /proc/version 2>/dev/null && echo wsl || echo linux ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    *) echo unknown ;;
  esac
}
SNARE_OS="$(snare_os)"

# Process list as: PID PPID COMMAND  (BSD and procps differ)
snare_ps(){
  case "$SNARE_OS" in
    macos) ps -axww -o pid=,ppid=,command= 2>/dev/null ;;
    windows) ps -W -s 2>/dev/null | awk 'NR>1{pid=$1;ppid=$2;$1=$2=$3=$4="";sub(/^ +/,"");print pid,ppid,$0}' ;;
    *) ps -eo pid=,ppid=,args= --width 4096 2>/dev/null || ps -eo pid=,ppid=,args= 2>/dev/null ;;
  esac
}

# One process's full command line
snare_ps_cmd(){ # $1=pid
  case "$SNARE_OS" in
    macos) ps -ww -o command= -p "$1" 2>/dev/null ;;
    *)     ps -o args= -p "$1" 2>/dev/null ;;
  esac
}

# Network connections, one per line, containing remote addresses
snare_netlist(){
  if command -v lsof >/dev/null 2>&1; then lsof -nP -i 2>/dev/null
  elif command -v ss  >/dev/null 2>&1; then ss -tunp 2>/dev/null
  elif command -v netstat >/dev/null 2>&1; then netstat -anp 2>/dev/null
  fi
}
# PID owning a connection line (differs per tool)
snare_net_pid(){ # reads a line on stdin
  if command -v lsof >/dev/null 2>&1; then awk '{print $2}'
  else grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2
  fi
}

snare_open(){ # open a URL/file in the desktop default handler
  case "$SNARE_OS" in
    macos)   open "$1" ;;
    windows) start "" "$1" 2>/dev/null || cmd.exe /c start "" "$1" ;;
    wsl)     command -v wslview >/dev/null && wslview "$1" || cmd.exe /c start "" "$1" ;;
    *)       command -v xdg-open >/dev/null && xdg-open "$1" >/dev/null 2>&1 || \
             { echo; ylw "  no xdg-open — paste this into your browser/mail client:"; echo "$1"; } ;;
  esac
}

snare_desktop_notify(){ # $1=message
  case "$SNARE_OS" in
    macos) osascript -e "display notification \"$1\" with title \"snare\" sound name \"Basso\"" >/dev/null 2>&1 ;;
    linux|wsl) command -v notify-send >/dev/null && notify-send -u critical "snare" "$1" >/dev/null 2>&1 ;;
    windows) powershell.exe -NoProfile -Command "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[System.Windows.Forms.MessageBox]::Show('$1','snare')" >/dev/null 2>&1 ;;
  esac
  return 0
}
