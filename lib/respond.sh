# shellcheck shell=bash
# respond.sh — one guided incident response instead of nine commands.
#
# Someone who has just found fifteen infected repositories should not have to
# choose between nine commands and read a manual to learn the right order. The
# order matters: credentials are this family's objective, and cleaning a repo
# from a still-infected machine simply lets it re-inject.

RESPOND_STATE="$SNARE_HOME/respond-state"
DOC_URL="https://nexlabz.github.io/snare/#infected"

# ---- state (resumable: this is an hour of work for a bad case) -------------
# Fails for a missing key on its own — not only under pipefail, which the
# old `grep | cut` relied on without saying so.
_rs_get(){
  [ -f "$RESPOND_STATE" ] || return 1
  local l; l="$(grep -m1 -F "$1=" "$RESPOND_STATE" 2>/dev/null | grep -m1 "^" )" || return 1
  case "$l" in "$1="*) printf '%s\n' "${l#*=}" ;; *) return 1 ;; esac
}
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

  # An agent must not drive this: it can approve a block and clean files.
  if _gate_under_agent; then
    red "snare respond has to be run by a person, in their own terminal."
    dim "  An agent cannot approve or clean up its own block."
    return 2
  fi

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

  # Saved progress is for resuming an INTERRUPTED run. A finished one used to
  # be replayed forever: every step said "already done — skipping" and the
  # summary repeated a month-old "infected repos found: 2" without naming them.
  _respond_fresh_if_finished
  _rs_get started >/dev/null 2>&1 || _rs_set started "$(date '+%Y-%m-%dT%H:%M:%S')"

  _respond_gate || { _respond_end; return 0; }
  _respond_triage
  _respond_rotate
  _respond_machine
  _respond_scan
  _respond_fix
  _respond_notify
  _respond_verify
  _respond_end
}

_respond_end(){
  _step "Done"
  echo "  Summary of this run:"
  _respond_status
  echo
  dim "  Re-run 'snare respond' any time; it picks up where you left off."
  dim "  Start over with: snare respond --reset"
}

_respond_fresh_if_finished(){
  _rs_done verify || return 0
  echo
  dim "  Your last clean-up (started $(_rs_get started)) finished — starting a fresh check."
  dim "  (its record is kept in $RESPOND_STATE.prev)"
  mv -f "$RESPOND_STATE" "$RESPOND_STATE.prev" 2>/dev/null
}

_respond_status(){
  local s
  for s in triage rotate machine scan fix notify verify; do
    if _rs_done "$s"; then grn "    $s: done"
    else dim "    $s: not yet"; fi
  done
  local n r; n="$(_rs_get infected_count 2>/dev/null)"
  [ -n "$n" ] && echo "    infected repos found: $n"
  for r in $(_rs_get flagged_list 2>/dev/null | tr ',' ' '); do
    if _rs_get "fixed_$r" >/dev/null 2>&1; then grn "      $r — cleaned"
    else ylw "      $r — NOT cleaned yet"; fi
  done
  _rs_get gate_summary >/dev/null 2>&1 && echo "    what the gate stopped: $(_rs_get gate_summary)"
  [ "$(_rs_get rotated 2>/dev/null)" = deferred ] && \
    ylw "    credentials: NOT rotated — do this, it is the whole point"
}

# ---- first: what the gate just stopped ------------------------------------
# The gate's banner sends the person here. So start with THAT — each place it
# stopped, re-checked now, with where to look and what is suspected — and let
# them decide per place before anything account-wide. Returns 1 when the
# person is done (it was all theirs), so the rest of the run is skipped.
_respond_gate(){
  [ -s "$GATE_PENDING" ] || return 0
  _step "What snare stopped"
  dim "  Re-checked now. These are SUSPICIONS with where to look — some turn out to"
  dim "  be a minified file or an unusual config. Look before you choose."
  local kind where cmd pdir pref res rc ans n=0 cleaned=0 allowed=0 left=0 keep
  keep="$(mktemp "${TMPDIR:-/tmp}/snarepend.XXXXXX")" || return 0
  while IFS="$(printf '\t')" read -r kind where cmd pdir pref <&4; do
    [ -z "$kind" ] && continue
    n=$((n + 1)); echo
    if [ "$kind" = incoming ]; then
      _respond_gate_incoming "$n" "$where" "$pdir" "$pref"; rc=$?
      case "$rc" in
        0) ;;                                   # clean now, or allowed
        3) allowed=$((allowed + 1)) ;;
        *) printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$where" "$cmd" "$pdir" "$pref" >> "$keep"; left=$((left + 1)) ;;
      esac
      continue
    fi
    if [ ! -d "$where" ]; then dim "  $n. $where — no longer exists"; continue; fi
    res="$(SNARE_GATE_TMP="${TMPDIR:-/tmp}" _gate_tree "$where" fresh)"; rc=$?
    if [ "$rc" = 0 ]; then grn "  $n. $where — clean now (cleaned or allowed since)"; continue; fi
    echo "  $n. $where"
    if [ "$rc" != 1 ]; then
      ylw "     could not finish re-checking it:"; printf '%s\n' "$res" | sed 's/^/   /'
      printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$where" "$cmd" "$pdir" "$pref" >> "$keep"; left=$((left + 1)); continue
    fi
    printf '%s\n' "$res" | sed 's/^/   /'
    echo
    echo "     c  clean it — snare strips or removes what it flagged (backed up first,"
    echo "        changes staged for you to review, nothing committed or pushed)"
    echo "     a  it is mine and harmless — allow it (asks about each finding)"
    echo "     l  leave it for now — the gate keeps blocking here"
    printf '     Choose [c/a/L] '; IFS= read -r ans
    case "$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')" in
      c|clean) if _respond_clean_local "$where"; then cleaned=$((cleaned + 1))
               else printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$where" "$cmd" "$pdir" "$pref" >> "$keep"; left=$((left + 1)); fi ;;
      a|allow) _gate_allow "$where"
               if SNARE_GATE_TMP="${TMPDIR:-/tmp}" _gate_tree "$where" fresh >/dev/null; then allowed=$((allowed + 1))
               else printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$where" "$cmd" "$pdir" "$pref" >> "$keep"; left=$((left + 1)); fi ;;
      *)       printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$where" "$cmd" "$pdir" "$pref" >> "$keep"; left=$((left + 1))
               dim "     left — still blocked" ;;
    esac
  done 4< "$GATE_PENDING"
  mv -f "$keep" "$GATE_PENDING"
  [ -s "$GATE_PENDING" ] || rm -f "$GATE_PENDING"
  _rs_set gate_summary "$cleaned cleaned, $allowed allowed, $left still blocked"
  echo
  if [ "$cleaned" -eq 0 ]; then
    # Nothing confirmed as an attack: the full incident response (rotate every
    # credential, sweep the account) is out of proportion. Offer, don't impose.
    _ask "  Go on to the full clean-up anyway (credentials, this machine, your GitHub repos)?" n \
      || { _rs_set step_verify "done"; return 1; }
  else
    red "  You confirmed $cleaned as real. Code from that payload may already have run"
    red "  here, so the full clean-up follows — credentials first."
  fi
  return 0
}

# Something the gate stopped before it arrived: a branch, a pull, a clone.
# Re-check it now and let the person allow it — this is the person's own
# repository far more often than not, so "wait for its owner" was no answer.
# Returns 0 clean now, 3 allowed, 1 still blocked.
_respond_gate_incoming(){ # $1=n $2=label $3=dir $4=ref|url
  local n="$1" label="$2" dir="$3" ref="$4" out rc ans target
  if [ -n "$dir" ]; then target="$dir"
    [ -d "$dir" ] || { dim "  $n. $label — that repository is gone"; return 0; }
  else target="$ref"; ref=""; fi
  [ -n "$target" ] || { echo "  $n. $label"; dim "     (recorded by an older snare — re-run the command to check it again)"; return 0; }
  out="$(_gate_allow_scan "$target" "$ref" 2>/dev/null)"; rc=$?
  # Only what is still flagged once the person's earlier approvals count.
  if [ "$rc" = 1 ]; then
    local fp keepo="" l
    while IFS= read -r l; do
      fp="${l##*$'\t'}"
      grep -q "^$fp " "$GATE_ALLOW" 2>/dev/null || keepo="$keepo$l"$'\n'
    done <<< "$out"
    out="$keepo"; [ -n "$out" ] || rc=0
  fi
  if [ "$rc" = 0 ]; then grn "  $n. $label — clean now (changed or allowed since)"; return 0; fi
  echo "  $n. $label"
  dim  "     not on this machine yet — this is what would arrive:"
  if [ "$rc" = 2 ]; then ylw "     could not fetch it to look again: $out"; return 1; fi
  local path line what ex
  while IFS="$(printf '\t')" read -r _ path line what ex _; do
    [ -z "$path" ] && continue
    if [ "${line:-0}" -gt 0 ] 2>/dev/null; then echo "     $path:$line — $what"; else echo "     $path — $what"; fi
    [ -n "$ex" ] && echo "         ↳ $ex"
  done <<< "$out"
  echo
  echo "     a  it is mine and harmless — allow it (asks about each finding)"
  echo "     l  leave it — the gate keeps stopping it"
  [ -n "$dir" ] && dim "     (if this is your repository and it IS infected: fix it at the source"
  [ -n "$dir" ] && dim "      with 'snare fix <owner/repo>', then pull again)"
  printf '     Choose [a/L] '; IFS= read -r ans
  case "$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')" in
    a|allow) _gate_allow "$target" ${ref:+"$ref"}
             out="$(_gate_allow_scan "$target" "$ref" 2>/dev/null)"
             local left_=0 l2
             while IFS= read -r l2; do [ -z "$l2" ] && continue
               grep -q "^${l2##*$'\t'} " "$GATE_ALLOW" 2>/dev/null || left_=1; done <<< "$out"
             [ "$left_" = 0 ] && return 3; return 1 ;;
    *) dim "     left — still stopped"; return 1 ;;
  esac
}

# Clean one local checkout in place with the same cleaner `snare fix` uses.
# Backs up first: committed files come back with git, so the backup is what
# git could NOT give back — modified and untracked files.
_respond_clean_local(){
  local dir="$1" bk stamp list
  stamp="$(date '+%Y%m%dT%H%M%S')"
  bk="$SNARE_BACKUPS/local-$(basename "$dir")-$stamp.tar.gz"
  mkdir -p "$SNARE_BACKUPS" 2>/dev/null
  list="$("${GATE_GIT[@]}" -C "$dir" ls-files -m -o --exclude-standard 2>/dev/null | grep -v '^node_modules/' | head -5000)"
  if [ -n "$list" ]; then
    ( cd "$dir" && printf '%s\n' "$list" | tar -czf "$bk" -T - 2>/dev/null ) \
      || { red "     backup failed — not cleaning"; return 1; }
    dim "     backup of uncommitted files: $bk"
  fi
  # A fresh clone (what `snare fix` cleans) has a clean .git/config; this
  # checkout may not. Pin the settings that make git run a program — the same
  # set the gate uses — for every git call the cleaner makes.
  ( cd "$dir" && git(){ snare_safe_git "${GATE_GIT[@]:1}" "$@"; } && _fix_clean_tree local "$(ioc_pattern)" ) 2>&1 | sed 's/^/   /'
  if SNARE_GATE_TMP="${TMPDIR:-/tmp}" _gate_tree "$dir" fresh >/dev/null; then
    grn "     clean. Review with:  git -C '$dir' diff --cached"
    dim "     then commit it yourself. Committed files can be restored with git checkout."
    return 0
  fi
  ylw "     snare could not clean all of it automatically. Still flagged:"
  SNARE_GATE_TMP="${TMPDIR:-/tmp}" _gate_tree "$dir" fresh | sed 's/^/   /'
  dim "     These need a person: open each file at the line shown. If it is yours,"
  dim "     'snare gate allow' it; if not, delete the flagged part."
  return 1
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
    red "  $n repository(ies) flagged:"
    sed 's/^/    - /' "$flagged"
  fi
  _rs_set flagged_list "$(tr '\n' ',' < "$flagged" 2>/dev/null | sed 's/,$//')"
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
        skip|n) ylw "    left as it is — it is still infected, and the summary will say so"; continue ;;
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
