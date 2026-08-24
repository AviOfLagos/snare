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
    if command -v lsof >/dev/null 2>&1; then
      echo "--- files ---"; lsof -p "$pid" 2>/dev/null | head -80
      echo "--- net ---";   lsof -nP -a -i -p "$pid" 2>/dev/null
    fi
  } > "$out" 2>&1
  echo "$out"
}

guard_children(){ # $1=ppid
  if command -v pgrep >/dev/null 2>&1; then pgrep -P "$1" 2>/dev/null
  else snare_ps | awk -v p="$1" '$2==p{print $1}'; fi
}
guard_kill_tree(){
  local pid="$1" k
  for k in $(guard_children "$pid"); do guard_kill_tree "$k"; done
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
    snare_desktop_notify "Killed $pid ($reason)"
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
  done < <(snare_ps)

  # Any process holding a socket to a known C2, whatever it is named.
  local ip
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    for ip in ${SNARE_C2_IPS:-23.27.13.135}; do
      case "$line" in *"$ip"*)
        pid="$(printf '%s' "$line" | snare_net_pid)"; [ -z "$pid" ] && continue
        [ "$pid" = "$$" ] && continue
        cmd="$(snare_ps_cmd "$pid")"
        case "$cmd" in *snare*) continue;; esac
        guard_handle "$pid" "c2-connection:$ip" "$cmd"; found=1 ;;
      esac
    done
  done < <(snare_netlist)
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
    install)   guard_service install ;;
    uninstall) guard_service uninstall ;;
    start)     guard_service start ;;
    stop)      guard_service stop ;;
    log)       tail -f "$SNARE_LOGS/guard.log" ;;
    status)    guard_service status ;;
    *) echo "usage: snare guard [status|scan|install|uninstall|start|stop|log|run]" ;;
  esac
}

guard_service(){
  local action="$1"
  case "$SNARE_OS" in
    macos)        guard_svc_launchd "$action" ;;
    linux|wsl)    guard_svc_systemd "$action" ;;
    windows)      guard_svc_schtasks "$action" ;;
    *) die "unsupported OS for the background guard; use: snare guard scan" ;;
  esac
}

_guard_common_status(){
  echo "  detections logged: $(ls -1 "$SNARE_EVIDENCE" 2>/dev/null | wc -l | tr -d ' ')"
  echo "  log: $SNARE_LOGS/guard.log"
}

# ---- macOS: launchd -------------------------------------------------------
guard_svc_launchd(){
  local plist="$HOME/Library/LaunchAgents/com.snare.guard.plist"
  case "$1" in
    install)
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
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$SNARE_LOGS/guard.out</string>
  <key>StandardErrorPath</key><string>$SNARE_LOGS/guard.err</string>
</dict></plist>
PLIST
      plutil -lint "$plist" >/dev/null || die "generated plist is invalid"
      launchctl unload "$plist" 2>/dev/null; launchctl load "$plist" 2>&1
      sleep 1
      launchctl list | grep -q com.snare.guard && grn "guard installed and running" || red "guard failed to start" ;;
    uninstall) launchctl unload "$plist" 2>/dev/null; rm -f "$plist"; ylw "guard uninstalled" ;;
    start)     launchctl load   "$plist" 2>&1 && grn "started" ;;
    stop)      launchctl unload "$plist" 2>&1 && ylw "stopped" ;;
    status)
      if launchctl list 2>/dev/null | grep -q com.snare.guard; then
        grn "guard running (pid $(launchctl list | awk '/com.snare.guard/{print $1}'))"
      else ylw "guard not running — 'snare guard install' to enable at login"; fi
      _guard_common_status ;;
  esac
}

# ---- Linux / WSL: systemd user unit --------------------------------------
guard_svc_systemd(){
  local unit="$HOME/.config/systemd/user/snare-guard.service"
  if ! command -v systemctl >/dev/null 2>&1; then
    case "$1" in
      status) ylw "no systemd here. Run the guard yourself:"; echo "    nohup snare guard run --interval 1 >/dev/null 2>&1 &"; _guard_common_status ;;
      install) ylw "no systemd — add this to your shell profile or supervisor:"; echo "    nohup snare guard run --interval 1 >/dev/null 2>&1 &" ;;
      *) ylw "no systemd; manage 'snare guard run' yourself" ;;
    esac
    return 0
  fi
  case "$1" in
    install)
      mkdir -p "$(dirname "$unit")"
      cat > "$unit" <<UNIT
[Unit]
Description=snare guard — kills supply-chain malware loaders on sight

[Service]
Type=simple
ExecStart=/bin/bash $SNARE_ROOT/bin/snare guard run --interval 1
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
UNIT
      systemctl --user daemon-reload
      systemctl --user enable --now snare-guard.service 2>&1 | tail -2
      systemctl --user is-active --quiet snare-guard.service \
        && grn "guard installed and running" || red "guard failed to start (journalctl --user -u snare-guard)"
      dim "  tip: 'loginctl enable-linger $USER' keeps it running when logged out" ;;
    uninstall) systemctl --user disable --now snare-guard.service 2>/dev/null; rm -f "$unit"; systemctl --user daemon-reload; ylw "guard uninstalled" ;;
    start)     systemctl --user start snare-guard.service && grn "started" ;;
    stop)      systemctl --user stop  snare-guard.service && ylw "stopped" ;;
    status)
      if systemctl --user is-active --quiet snare-guard.service; then
        grn "guard running (pid $(systemctl --user show -p MainPID --value snare-guard.service))"
      else ylw "guard not running — 'snare guard install' to enable at login"; fi
      _guard_common_status ;;
  esac
}

# ---- Windows (Git Bash): Scheduled Task ----------------------------------
guard_svc_schtasks(){
  local name="snare-guard" bash_exe
  bash_exe="$(command -v bash)"
  case "$1" in
    install)
      schtasks //Create //TN "$name" //SC ONLOGON //RL LIMITED //F \
        //TR "\"$bash_exe\" -lc 'snare guard run --interval 1'" >/dev/null 2>&1 \
        && grn "scheduled task '$name' created (runs at logon)" || red "could not create the scheduled task"
      schtasks //Run //TN "$name" >/dev/null 2>&1 && grn "started" ;;
    uninstall) schtasks //Delete //TN "$name" //F >/dev/null 2>&1 && ylw "guard uninstalled" ;;
    start)     schtasks //Run  //TN "$name" >/dev/null 2>&1 && grn "started" ;;
    stop)      schtasks //End  //TN "$name" >/dev/null 2>&1 && ylw "stopped" ;;
    status)
      if schtasks //Query //TN "$name" >/dev/null 2>&1; then grn "scheduled task '$name' registered"
      else ylw "guard not registered — 'snare guard install'"; fi
      _guard_common_status ;;
  esac
}
