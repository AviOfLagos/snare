# shellcheck shell=bash
# guard.sh — live process monitor. Detects, snapshots and kills the loader.

guard_pattern(){
  # Deliberately TIGHTER than iocs.txt: this decides what gets KILLED.
  echo '23\.27\.13\.135|/0x/cl[bs]|/0x/ls|/verify-human/|q4FZkxX|A8-3379-6|global\[._t_s.\]|global\[._V.\]|0xa322[eE]5f3[dD]311[dD]3080e6f0121063e9a[dD][cC]2490[eE]f1a|node[[:space:]]+.*-e[[:space:]]+.*global\[|osascript.*(generalPasteboard|NSPasteboard)|setup_bun\.js|bun_environment\.js'
}

guard_capture(){ # $1=pid $2=reason -> prints evidence path
  local pid="$1" reason="$2" out
  out="$SNARE_EVIDENCE/$(date '+%Y%m%dT%H%M%S')-pid${pid}.txt"
  {
    echo "detected_at: $(date '+%F %T')"; echo "reason: $reason"
    echo "--- ps ---";   ps -ww -o pid,ppid,pgid,uid,lstart,command -p "$pid" 2>&1
    echo "--- files ---"; lsof -p "$pid" 2>/dev/null | head -80
    echo "--- net ---";   lsof -nP -a -i -p "$pid" 2>/dev/null
  } > "$out" 2>&1
  echo "$out"
}

guard_kill_tree(){
  local pid="$1" k
  for k in $(pgrep -P "$pid" 2>/dev/null); do guard_kill_tree "$k"; done
  kill -9 "$pid" 2>/dev/null
}

guard_handle(){ # $1=pid $2=reason $3=cmd
  local pid="$1" reason="$2" cmd="$3" ev
  ev="$(guard_capture "$pid" "$reason")"
  local msg="[$(date '+%F %T')] DETECTED pid=$pid reason=$reason"
  echo "$msg" | tee -a "$SNARE_LOGS/guard.log"
  echo "  cmd: $(echo "$cmd" | cut -c1-200)" | tee -a "$SNARE_LOGS/guard.log"
  echo "  evidence: $ev" | tee -a "$SNARE_LOGS/guard.log"
  if [ "${GUARD_DRY:-0}" = "1" ]; then
    echo "  DRY-RUN: not killed" | tee -a "$SNARE_LOGS/guard.log"; return
  fi
  if guard_kill_tree "$pid"; then
    echo "  KILLED" | tee -a "$SNARE_LOGS/guard.log"
    osascript -e "display notification \"Killed $pid ($reason)\" with title \"snare\" sound name \"Basso\"" >/dev/null 2>&1 || true
  else
    echo "  kill failed (already gone?)" | tee -a "$SNARE_LOGS/guard.log"
  fi
}

guard_scan_once(){
  local found=0 pid ppid cmd exe base line pat
  pat="$(guard_pattern)"
  # Matched inside bash: the pattern is never placed in a child's argv.
  while read -r pid ppid cmd; do
    [ -z "$pid" ] || [ -z "$cmd" ] && continue
    [ "$pid" = "$$" ] && continue
    [ "$ppid" = "$$" ] && continue
    case "$cmd" in *snare*|*/.snare/*) continue;; esac
    # A command line that merely MENTIONS an IOC (a shell running grep, an
    # editor, this tool) must never be killed. Only interpreters can execute
    # an inline payload, so restrict cmdline kills to those.
    exe="${cmd%% *}"; base="${exe##*/}"
    case "$base" in
      node|nodejs|bun|deno|osascript|python|python3|ruby|perl|php) ;;
      *) continue ;;
    esac
    if [[ "$cmd" =~ $pat ]]; then guard_handle "$pid" "cmdline-ioc" "$cmd"; found=1; fi
  done < <(ps -axww -o pid=,ppid=,command= 2>/dev/null)

  # Any process holding a socket to a known C2, whatever it is named.
  local ip
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    for ip in ${SNARE_C2_IPS:-23.27.13.135}; do
      case "$line" in *"$ip"*)
        pid="$(echo "$line" | awk '{print $2}')"; [ -z "$pid" ] && continue
        [ "$pid" = "$$" ] && continue
        cmd="$(ps -ww -o command= -p "$pid" 2>/dev/null)"
        case "$cmd" in *snare*) continue;; esac
        guard_handle "$pid" "c2-connection:$ip" "$cmd"; found=1 ;;
      esac
    done
  done < <(lsof -nP -i 2>/dev/null)
  return $found
}

cmd_guard(){
  local sub="${1:-status}"; shift || true
  case "$sub" in
    scan)
      GUARD_DRY="${GUARD_DRY:-0}"
      [ "${1:-}" = "--dry-run" ] && GUARD_DRY=1
      if guard_scan_once; then grn "clean"; else red "detections found (see $SNARE_LOGS/guard.log)"; return 1; fi ;;
    run)
      local iv=1
      while [ $# -gt 0 ]; do
        case "$1" in --interval) iv="${2:-1}"; shift ;; esac; shift
      done
      echo "[$(date '+%F %T')] guard started (interval=${iv}s, pid=$$)" | tee -a "$SNARE_LOGS/guard.log"
      trap 'echo "[$(date "+%F %T")] guard stopped" >> "$SNARE_LOGS/guard.log"; exit 0' INT TERM
      while true; do guard_scan_once || true; sleep "$iv"; done ;;
    install)  guard_install ;;
    uninstall) guard_uninstall ;;
    start)  launchctl load   "$HOME/Library/LaunchAgents/com.snare.guard.plist" 2>&1 && grn "started" ;;
    stop)   launchctl unload "$HOME/Library/LaunchAgents/com.snare.guard.plist" 2>&1 && ylw "stopped" ;;
    log)    tail -f "$SNARE_LOGS/guard.log" ;;
    status)
      if launchctl list 2>/dev/null | grep -q com.snare.guard; then
        grn "guard running (pid $(launchctl list | awk '/com.snare.guard/{print $1}'))"
      else ylw "guard not running — 'snare guard install' to enable at login"; fi
      echo "  detections logged: $(ls -1 "$SNARE_EVIDENCE" 2>/dev/null | wc -l | tr -d ' ')"
      echo "  log: $SNARE_LOGS/guard.log" ;;
    *) echo "usage: snare guard [status|scan|install|uninstall|start|stop|log|run]" ;;
  esac
}

guard_install(){
  local plist="$HOME/Library/LaunchAgents/com.snare.guard.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.snare.guard</string>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string><string>$SNARE_ROOT/bin/snare</string>
    <string>guard</string><string>run</string><string>--interval</string><string>1</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$SNARE_LOGS/guard.out</string>
  <key>StandardErrorPath</key><string>$SNARE_LOGS/guard.err</string>
</dict></plist>
PLIST
  plutil -lint "$plist" >/dev/null || die "generated plist is invalid"
  launchctl unload "$plist" 2>/dev/null
  launchctl load   "$plist" 2>&1
  sleep 1
  launchctl list | grep -q com.snare.guard && grn "guard installed and running" || red "guard failed to start"
}

guard_uninstall(){
  local plist="$HOME/Library/LaunchAgents/com.snare.guard.plist"
  launchctl unload "$plist" 2>/dev/null; rm -f "$plist"; ylw "guard uninstalled"
}
