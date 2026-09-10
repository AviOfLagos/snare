# shellcheck shell=bash
# doctor.sh — is THIS machine clean, and is snare actually watching it?
#
# Every check here was macOS-only until a Linux host ran it during a live
# infection and was told its persistence spots were "empty" three times — the
# three directories being macOS paths that do not exist on Linux, so nothing
# was ever looked at. A checker that reports clean because it looked in the
# wrong place is worse than no checker.

# One entry per persistence directory, with the count of things in it.
_doctor_spots(){
  local d n
  case "$SNARE_OS" in
    macos)
      set -- "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons ;;
    linux|wsl)
      set -- "$HOME/.config/systemd/user" "$HOME/.local/share/systemd/user" \
             "$HOME/.config/autostart" "/etc/cron.d" ;;
    windows)
      set -- "$(cygpath -u "${APPDATA:-}" 2>/dev/null)/Microsoft/Windows/Start Menu/Programs/Startup" ;;
    *)
      set -- "$HOME/.config/autostart" ;;
  esac
  for d in "$@"; do
    [ -z "$d" ] && continue
    if [ ! -d "$d" ]; then
      dim "  $d: not present on this system"
      continue
    fi
    # find, not ls|grep: a filename containing a newline would break the count,
    # and this counts persistence entries — the exact place to expect a
    # deliberately awkward filename. snare's own units are not findings.
    n="$(find "$d" -maxdepth 1 -mindepth 1 \
           ! -name 'com.snare*' ! -name 'snare-*' 2>/dev/null | wc -l | tr -d ' ')"
    if [ "${n:-0}" -gt 0 ]; then
      ylw "  $d: $n entry(ies) — review"
      find "$d" -maxdepth 1 -mindepth 1 ! -name 'com.snare*' ! -name 'snare-*' 2>/dev/null \
        | sed 's#.*/#        #' | head -8
    else
      grn "  $d: empty"
    fi
  done

  # cron is not macOS-specific and is where the RAT on the reference host lived.
  if crontab -l >/dev/null 2>&1; then
    ylw "  crontab: present — review"
    crontab -l 2>/dev/null | grep -v '^[[:space:]]*#' | grep . | sed 's/^/        /' | head -10
  else
    grn "  crontab: none"
  fi
}

# Where npm actually lives, WITHOUT running npm to ask. On the host this was
# written for, running npm at all was the thing that executed the loader.
_doctor_npm_roots(){
  local n d
  n="$(command -v node 2>/dev/null)"
  [ -n "$n" ] && d="$(cd "$(dirname "$n")/.." 2>/dev/null && pwd)" \
    && [ -d "$d/lib/node_modules/npm" ] && printf '%s\n' "$d/lib/node_modules/npm"
  for d in "$HOME"/.nvm/versions/node/*/lib/node_modules/npm \
           "$HOME"/.config/nvm/versions/node/*/lib/node_modules/npm \
           /usr/lib/node_modules/npm /usr/local/lib/node_modules/npm \
           /opt/homebrew/lib/node_modules/npm; do
    [ -d "$d" ] && printf '%s\n' "$d"
  done
}

# The package manager is a file like any other, and nothing was checking it.
# The documented route on the reference host was npm's own lib/cli.js rewritten
# in place — 1.4MB appended after 200 spaces — so every `npm` ran the loader.
# `ignore-scripts=true` was set and did not help: it was not a package script.
_doctor_node(){
  local root f found=0 pattern seen=0
  pattern="$(ioc_pattern)"
  while IFS= read -r root; do
    [ -z "$root" ] && continue
    seen=1
    while IFS= read -r f; do
      [ -z "$f" ] || [ ! -f "$f" ] && continue
      if grep -qE '[^[:space:]][[:space:]]{50,}[^[:space:]]' "$f" 2>/dev/null; then
        red "  [!] $f — code hidden past a run of whitespace"; found=1
      elif grep -qE "$pattern" "$f" 2>/dev/null; then
        red "  [!] $f — matches a known IOC"; found=1
      fi
    done < <(find "$root/lib" "$root/bin" -maxdepth 1 -type f -name '*.js' 2>/dev/null)
  done < <(_doctor_npm_roots | sort -u)
  [ "$seen" = 0 ] && { dim "  no npm installation found to check"; return 0; }
  [ "$found" = 0 ] && grn "  npm's own files are intact"

  # $HOME/.node_modules is a legacy Node global resolution path. Almost nobody
  # populates it deliberately; on the reference host it held the RAT's axios
  # and socket.io-client so a dropped script could require them from anywhere.
  if [ -d "$HOME/.node_modules" ]; then
    ylw "  [~] ~/.node_modules exists — legacy global module path, rarely deliberate"
    ls -1 "$HOME/.node_modules/node_modules" 2>/dev/null | head -6 | sed 's/^/        /'
  fi

  # An injected --require runs before any program's own code.
  if [ -n "${NODE_OPTIONS:-}" ]; then
    ylw "  [~] NODE_OPTIONS is set: $NODE_OPTIONS"
  fi
  local rc
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.zshenv"; do
    [ -f "$rc" ] || continue
    grep -qE '^[^#]*NODE_OPTIONS.*(--require|--import)' "$rc" 2>/dev/null \
      && ylw "  [~] $rc sets NODE_OPTIONS with --require/--import — read it"
  done
  return 0
}

cmd_doctor(){
  hdr "This machine"
  if guard_scan_once >/dev/null 2>&1; then grn "  no malicious process running"
  else red "  DETECTIONS — see $SNARE_LOGS/guard.log"; fi
  # Was launchctl-only, so on Linux and Windows this said "not installed" no
  # matter what the guard was doing.
  case "$(guard_state)" in
    running) grn "  guard is running" ;;
    stopped) ylw "  guard is installed but NOT running (snare guard start)" ;;
    *)       ylw "  guard not installed (snare guard install)" ;;
  esac
  if [ -s "$SNARE_LOGS/origins.log" ]; then
    local n; n="$(grep -c '^\[' "$SNARE_LOGS/origins.log" 2>/dev/null | tr -d ' ')"
    ylw "  ${n:-0} past detection(s) recorded — snare guard origins"
  fi

  hdr "Persistence spots"
  _doctor_spots

  hdr "Node and npm"
  _doctor_node

  # Refresh the update cache here: doctor already waits on the network, so this
  # adds nothing a user notices, and it means the nudge works even when the
  # detached background refresh does not.
  snare_update_refresh 2>/dev/null || true

  hdr "GitHub"
  if gh auth status >/dev/null 2>&1; then
    grn "  authenticated as $(gh_user)"
    echo "  token scopes: $(gh api -i user 2>/dev/null | awk -F': ' '/^[Xx]-[Oo]auth-[Ss]copes:/{print $2}' | tr -d '\r')"
    echo "  repos reachable: $(gh api --paginate 'user/repos?affiliation=owner,collaborator,organization_member&per_page=100' --jq '.[].full_name' 2>/dev/null | sort -u | wc -l | tr -d ' ')"
  else ylw "  not authenticated — run: gh auth login"; fi
  echo
  dim "  next: snare respond    — guided clean-up in the right order"
  dim "        snare scan github — just look, change nothing"
}
