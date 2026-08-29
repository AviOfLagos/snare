# shellcheck shell=bash
# respond.sh — one guided incident response instead of nine commands.
#
# Someone who has just found fifteen infected repositories should not have to
# choose between nine commands and read a manual to learn the right order. The
# order matters: credentials are this family's objective, and cleaning a repo
# from a still-infected machine simply lets it re-inject.

RESPOND_STATE="$SNARE_HOME/respond-state"
DOC_URL="https://avioflagos.github.io/snare/#infected"

# ---- state (resumable: this is an hour of work for a bad case) -------------
_rs_get(){ [ -f "$RESPOND_STATE" ] || return 1; grep -m1 "^$1=" "$RESPOND_STATE" 2>/dev/null | cut -d= -f2-; }
_rs_set(){
  mkdir -p "$(dirname "$RESPOND_STATE")" 2>/dev/null
  touch "$RESPOND_STATE"
  grep -v "^$1=" "$RESPOND_STATE" 2>/dev/null > "$RESPOND_STATE.tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$RESPOND_STATE.tmp"
  mv "$RESPOND_STATE.tmp" "$RESPOND_STATE"
}
_rs_done(){ [ "$(_rs_get "step_$1" 2>/dev/null)" = "done" ]; }

# ---- prompts ---------------------------------------------------------------
# $1 question, $2 default (y|n). Returns 0 for yes.
_ask(){
  local q="$1" def="${2:-n}" ans hint
  [ "$def" = y ] && hint="[Y/n]" || hint="[y/N]"
  printf '%s %s ' "$q" "$hint"
  read -r ans
  ans="$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')"
  [ -z "$ans" ] && ans="$def"
  [ "$ans" = y ] || [ "$ans" = yes ]
}

# $1 question -> prints one of: y n all skip
_ask4(){
  local q="$1" ans
  printf '%s [y/N/all/skip] ' "$q"
  read -r ans
  case "$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')" in
    y|yes) printf 'y' ;;
    a|all) printf 'all' ;;
    s|skip) printf 'skip' ;;
    *) printf 'n' ;;
  esac
}

_step(){ printf '\n%s── %s ──%s\n' "$C_BLD" "$*" "$C_OFF"; }

# ---------------------------------------------------------------------------
cmd_respond(){
  local reset=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --reset) reset=1 ;;
      --status) _respond_status; return 0 ;;
      *) red "unknown flag: $1"; return 2 ;;
    esac; shift
  done
  [ "$reset" = 1 ] && { rm -f "$RESPOND_STATE"; grn "  progress reset"; }

  # Never prompt where nobody can answer, and never assume yes.
  if [ ! -t 0 ] || [ ! -t 1 ] || [ -n "${CI:-}" ]; then
    red "snare respond is interactive and will not run unattended."
    echo "  Run it in a terminal, or use the individual commands:"
    echo "      snare rotate ; snare doctor ; snare scan github ; snare fix <repo>"
    return 2
  fi

  hdr "snare respond"
  echo "  A guided clean-up, in the order that actually works."
  dim  "  Nothing is changed or pushed without you saying so."
  dim  "  Stop any time with Ctrl-C — progress is saved and resumes here."
  dim  "  Full walkthrough: $DOC_URL"
  _rs_get started >/dev/null 2>&1 || _rs_set started "$(date '+%Y-%m-%dT%H:%M:%S')"

  _respond_triage
  _respond_rotate
  _respond_machine
  _respond_scan
  _respond_fix
  _respond_notify
  _respond_verify

  _step "Done"
  echo "  Summary of this run:"
  _respond_status
  echo
  dim "  Re-run 'snare respond' any time; it picks up where you left off."
  dim "  Start over with: snare respond --reset"
}

_respond_status(){
  local s
  for s in triage rotate machine scan fix notify verify; do
    if _rs_done "$s"; then grn "    $s: done"
    else dim "    $s: not yet"; fi
  done
  local n; n="$(_rs_get infected_count 2>/dev/null)"
  [ -n "$n" ] && echo "    infected repos found: $n"
  [ "$(_rs_get rotated 2>/dev/null)" = deferred ] && \
    ylw "    credentials: NOT rotated — do this, it is the whole point"
}

# ---- 0. triage -------------------------------------------------------------
_respond_triage(){
  _step "1 of 6 · What state is this machine in?"
  if guard_scan_once >/dev/null 2>&1; then
    grn "  no malicious process running right now"
    dim  "  That does not mean you were never infected: the loader runs when a"
    dim  "  build runs or an editor opens the folder, then exits. A clean process"
    dim  "  check alongside infected repositories is expected, not a contradiction."
  else
    red "  DETECTIONS on this machine — see $SNARE_LOGS/guard.log"
    _rs_set machine_dirty yes
  fi
  _rs_set step_triage "done"
}

# ---- 1. rotate -------------------------------------------------------------
_respond_rotate(){
  _rs_done rotate && { echo; dim "  (credentials already handled — skipping)"; return 0; }
  _step "2 of 6 · Rotate credentials — do this before touching any repository"
  echo "  Stealing credentials is what this family is FOR. The file in your"
  echo "  repository is delivery, not payload; removing it does not un-steal a"
  echo "  token. Some of this snare can do for you."
  echo

  # npm tokens: the highest-priority credential, and fully automatable. A
  # stolen npm write token lets the worm publish trojanised versions of the
  # victim's other packages — that is how one laptop becomes a supply chain.
  if command -v npm >/dev/null 2>&1; then
    echo "  npm tokens (the ones that matter most):"
    local toks; toks="$(npm token list 2>/dev/null | head -20)"
    if [ -n "$toks" ]; then
      echo "$toks" | sed 's/^/    /'
      if _ask "  Revoke npm tokens now? (you will create fresh ones after)" n; then
        local id
        for id in $(npm token list --parseable 2>/dev/null | cut -f1 | head -20); do
          [ -z "$id" ] && continue
          npm token revoke "$id" >/dev/null 2>&1 && grn "    revoked $id" || ylw "    could not revoke $id"
        done
      fi
    else
      dim "    none found (or npm is not logged in)"
    fi
  fi

  # SSH keys on the GitHub account.
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    echo
    echo "  SSH keys on your GitHub account:"
    gh ssh-key list 2>/dev/null | head -10 | sed 's/^/    /' || dim "    none"
  fi

  echo
  echo "  These need a browser — snare cannot revoke them for you:"
  echo "    GitHub tokens   https://github.com/settings/tokens"
  echo "    OAuth apps      https://github.com/settings/applications"
  echo "    npm tokens      https://www.npmjs.com/settings/~/tokens"
  if _ask "  Open those pages now?" y; then
    local opener=""
    command -v open >/dev/null 2>&1 && opener=open
    [ -z "$opener" ] && command -v xdg-open >/dev/null 2>&1 && opener=xdg-open
    [ -z "$opener" ] && command -v start >/dev/null 2>&1 && opener=start
    if [ -n "$opener" ]; then
      "$opener" "https://github.com/settings/tokens" >/dev/null 2>&1
      "$opener" "https://www.npmjs.com/settings/~/tokens" >/dev/null 2>&1
      grn "  opened"
    else
      ylw "  could not find a browser opener — the URLs are above"
    fi
  fi

  echo
  dim "  Also rotate, when you get to them: cloud keys (AWS — check Secrets"
  dim "  Manager per region — GCP, Azure), .env files in any project you had"
  dim "  open, SSH keys, kubeconfig, Vault, database URLs, VPN, AI-service keys,"
  dim "  wallet keys and seed phrases. And treat anything you copied to your"
  dim "  clipboard while infected as seen — this family has a clipboard stealer."
  echo
  if _ask "  Have you rotated the important ones (npm + GitHub)?" n; then
    _rs_set rotated yes; _rs_set step_rotate "done"
    grn "  good — that is the part that stops this spreading further"
  else
    # Deliberately not a wall. A blocked user abandons the whole clean-up; a
    # warned one finishes and comes back. But it is recorded and re-raised.
    _rs_set rotated deferred; _rs_set step_rotate "done"
    ylw "  noted — continuing, but this is the step that actually matters."
    ylw "  You will be reminded before anything is pushed."
  fi
}

# ---- 2. machine ------------------------------------------------------------
_respond_machine(){
  _rs_done machine && { echo; dim "  (machine already handled — skipping)"; return 0; }
  _step "3 of 6 · The machine you push from"
  echo "  This family injects into commits as they leave an already-infected"
  echo "  machine. Cleaning repositories first is wasted work if this one is"
  echo "  still compromised — it re-injects into whatever you just fixed."
  echo
  cmd_doctor 2>&1 | sed 's/^/  /'
  echo
  if [ "$(_rs_get guard_installed 2>/dev/null)" != yes ]; then
    if _ask "  Install the background guard (kills the loader on sight, from login)?" y; then
      cmd_guard install 2>&1 | sed 's/^/    /'
      _rs_set guard_installed yes
    fi
  fi
  _rs_set step_machine "done"
}

# ---- 3. scan ---------------------------------------------------------------
_respond_scan(){
  _rs_done scan && { echo; dim "  (scan already done — skipping; --reset to rescan)"; return 0; }
  _step "4 of 6 · Find what is infected"
  local flagged="$SNARE_LOGS/flagged.txt"
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if _ask "  Scan every GitHub repository you can reach? (read-only)" y; then
      cmd_scan_github 2>&1 | tail -30 | sed 's/^/  /'
    fi
  else
    ylw "  Not authenticated to GitHub, so the account-wide scan is unavailable."
    dim  "  Run 'gh auth login' and re-run snare respond to include it."
  fi
  if git rev-parse --git-dir >/dev/null 2>&1; then
    echo
    if _ask "  Also deep-scan the repository you are standing in (full history)?" y; then
      cmd_scan_repo "$PWD" 2>&1 | tail -20 | sed 's/^/  /'
    fi
  fi
  local n=0
  [ -s "$flagged" ] && n="$(grep -c . "$flagged" 2>/dev/null | tr -d ' ')"
  _rs_set infected_count "$n"
  _rs_set step_scan "done"
  echo
  if [ "${n:-0}" -eq 0 ]; then
    grn "  Nothing flagged at branch tips."
    dim "  History-only infections are invisible to the API scan — run"
    dim "  'snare scan repo <clone>' on anything you care about."
  else
    red "  $n repository(ies) flagged."
  fi
}

# ---- 4. fix ----------------------------------------------------------------
_respond_fix(){
  local flagged="$SNARE_LOGS/flagged.txt"
  [ -s "$flagged" ] || { echo; dim "  (nothing flagged — nothing to fix)"; _rs_set step_fix "done"; return 0; }
  _rs_done fix && { echo; dim "  (fixes already applied — skipping)"; return 0; }

  _step "5 of 6 · Clean the repositories"
  if [ "$(_rs_get rotated 2>/dev/null)" = deferred ]; then
    ylw "  Reminder: you have not rotated your credentials yet."
    ylw "  Whoever took them still has them, and cleaning repos does not change"
    ylw "  that. Consider stopping here and doing it first."
    _ask "  Continue anyway?" n || { ylw "  stopped — run 'snare rotate', then come back"; return 0; }
  fi

  # The destructive choice is made ONCE, deliberately — not per repository,
  # where a rhythm of y-y-y would carry someone through it by accident.
  local mode; mode="$(_rs_get fix_mode 2>/dev/null)"
  if [ -z "$mode" ]; then
    echo
    echo "  Two ways to clean:"
    echo "    tips   — remove the payload from every branch. Safe: nobody re-clones."
    echo "    purge  — also erase it from history. Thorough, but EVERY commit SHA"
    echo "             changes: every existing clone breaks and must be re-cloned,"
    echo "             not pulled. Forks and PR refs keep the old objects anyway."
    printf '  Which? [tips/purge] '
    local m; read -r m
    case "$(printf '%s' "$m" | tr '[:upper:]' '[:lower:]')" in
      purge|p) mode=purge ;;
      *) mode=tips ;;
    esac
    _rs_set fix_mode "$mode"
  fi
  echo "  Mode: $mode"
  echo

  local applyall=0 r choice
  while IFS= read -r r; do
    [ -z "$r" ] && continue
    _rs_get "fixed_$r" >/dev/null 2>&1 && { dim "  $r — already done"; continue; }
    echo
    echo "  ── $r"
    if [ "$applyall" = 0 ]; then
      choice="$(_ask4 "  Clean it? ($mode)")"
      case "$choice" in
        all)  applyall=1 ;;
        skip) dim "    skipped"; continue ;;
        n)    dim "    skipped"; continue ;;
      esac
    fi
    if [ "$mode" = purge ]; then
      cmd_fix "$r" --purge-history --push 2>&1 | tail -12 | sed 's/^/    /'
    else
      cmd_fix "$r" --push 2>&1 | tail -12 | sed 's/^/    /'
    fi
    _rs_set "fixed_$r" "done"
  done < "$flagged"
  _rs_set step_fix "done"
}

# ---- 5. notify -------------------------------------------------------------
_respond_notify(){
  local flagged="$SNARE_LOGS/flagged.txt"
  [ -s "$flagged" ] || { _rs_set step_notify "done"; return 0; }
  _rs_done notify && { echo; dim "  (already notified — skipping)"; return 0; }

  _step "6 of 6 · Tell the people who share these repositories"
  echo "  They may be infected from the same source. And if you purged history,"
  echo "  their clones are broken right now with no explanation."
  echo
  local r
  while IFS= read -r r; do
    [ -z "$r" ] && continue
    _rs_get "notified_$r" >/dev/null 2>&1 && continue
    if _ask "  File a security issue on $r?" y; then
      cmd_notify "$r" --issue 2>&1 | tail -6 | sed 's/^/    /'
      _rs_set "notified_$r" "done"
    fi
  done < "$flagged"
  _rs_set step_notify "done"
}

# ---- 6. verify -------------------------------------------------------------
_respond_verify(){
  _step "Verify — re-reading rather than trusting what just happened"
  local flagged="$SNARE_LOGS/flagged.txt"
  if [ -s "$flagged" ] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if _ask "  Re-scan to confirm the fixes actually landed?" y; then
      cmd_scan_github 2>&1 | tail -12 | sed 's/^/  /'
    fi
  fi
  _rs_set step_verify "done"
  echo
  if [ "$(_rs_get rotated 2>/dev/null)" = deferred ]; then
    red "  Still outstanding: your credentials were never rotated."
    red "  That is the one thing this whole exercise was protecting."
    dim  "  Run: snare rotate"
  fi
}
