# shellcheck shell=bash
# report.sh — scheduled reports and notifications. Closes #7.
#
# Deliberately no email: SMTP credentials and deliverability are a liability
# for a security tool. A report file plus a native desktop notification does
# the same job with nothing to steal.

SNARE_REPORTS="$SNARE_HOME/reports"
mkdir -p "$SNARE_REPORTS" 2>/dev/null

# Desktop notification, best-effort and never fatal.
snare_notify_desktop(){
  local title="$1" msg="$2"
  case "$SNARE_OS" in
    macos)
      # Escape double quotes for AppleScript.
      local t="${title//\"/\\\"}" m="${msg//\"/\\\"}"
      osascript -e "display notification \"$m\" with title \"$t\"" >/dev/null 2>&1 ;;
    linux|wsl)
      command -v notify-send >/dev/null 2>&1 && notify-send "$title" "$msg" >/dev/null 2>&1 ;;
  esac
  return 0
}

# snare report [--json] [--quiet] [--notify]
#   Scans this machine and the current repo (if any), writes a timestamped
#   report, and exits non-zero when something is found so CI and timers can
#   act on it.
cmd_report(){
  local json=0 quiet=0 notify=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --json)   json=1 ;;
      --quiet)  quiet=1 ;;
      --notify) notify=1 ;;
      *) red "unknown flag: $1"; return 2 ;;
    esac; shift
  done

  local stamp; stamp="$(date '+%Y%m%dT%H%M%S')"
  local out="$SNARE_REPORTS/report-$stamp.txt"
  local findings=0 guard_ok=1 repo_out="" host; host="$(hostname 2>/dev/null)"

  {
    echo "snare report — $(date)"
    echo "host: $host"
    echo "version: $SNARE_VERSION"
    echo
  } > "$out"

  # 1. machine
  if guard_scan_once >/dev/null 2>&1; then
    echo "machine: clean (no malicious process running)" >> "$out"
  else
    echo "machine: DETECTIONS — see $SNARE_LOGS/guard.log" >> "$out"
    guard_ok=0; findings=$((findings+1))
  fi

  # 2. current repo, when we are standing in one
  if git rev-parse --git-dir >/dev/null 2>&1; then
    repo_out="$(cmd_scan_repo "$PWD" 2>&1)"
    local n; n="$(echo "$repo_out" | grep -c '\[!\]')"
    echo "repo: $PWD — $n finding(s)" >> "$out"
    [ "$n" -gt 0 ] && { echo "$repo_out" | grep '\[!\]' >> "$out"; findings=$((findings+n)); }
  else
    echo "repo: (not inside a git repository — skipped)" >> "$out"
  fi

  echo >> "$out"
  echo "total findings: $findings" >> "$out"

  if [ "$json" = 1 ]; then
    printf '{"timestamp":"%s","host":"%s","version":"%s","machine_clean":%s,"findings":%s,"report":"%s"}\n' \
      "$stamp" "$host" "$SNARE_VERSION" \
      "$([ "$guard_ok" = 1 ] && echo true || echo false)" \
      "$findings" "$out"
  elif [ "$quiet" = 0 ]; then
    cat "$out"
    echo; dim "  saved: $out"
  fi

  if [ "$notify" = 1 ] && [ "$findings" -gt 0 ]; then
    snare_notify_desktop "snare: $findings finding(s)" "on $host — see $out"
  fi

  # Prune: keep the most recent 60 reports.
  ls -1t "$SNARE_REPORTS"/report-*.txt 2>/dev/null | tail -n +61 | while IFS= read -r old; do
    rm -f "$old"
  done

  [ "$findings" -gt 0 ] && return 1
  return 0
}

# ---------------------------------------------------------------- scheduling
_sched_label="com.snare.report"

cmd_schedule(){
  local sub="${1:-status}"; shift || true
  case "$sub" in
    install)   _sched_install "$@" ;;
    uninstall) _sched_uninstall ;;
    status)    _sched_status ;;
    *) echo "usage: snare schedule [install --daily|--weekly|uninstall|status]" ;;
  esac
}

_sched_install(){
  local when=daily
  while [ $# -gt 0 ]; do
    case "$1" in --daily) when=daily ;; --weekly) when=weekly ;; esac; shift
  done
  local self="$SNARE_ROOT/bin/snare"

  case "$SNARE_OS" in
    macos)
      local plist="$HOME/Library/LaunchAgents/$_sched_label.plist"
      mkdir -p "$HOME/Library/LaunchAgents"
      # daily 09:00; weekly = Monday 09:00
      local cal='<key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer>'
      [ "$when" = weekly ] && cal="$cal<key>Weekday</key><integer>1</integer>"
      cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$_sched_label</string>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string><string>$self</string>
    <string>report</string><string>--quiet</string><string>--notify</string>
  </array>
  <key>StartCalendarInterval</key><dict>$cal</dict>
  <key>StandardOutPath</key><string>$SNARE_LOGS/report.out</string>
  <key>StandardErrorPath</key><string>$SNARE_LOGS/report.err</string>
</dict></plist>
PLIST
      launchctl unload "$plist" >/dev/null 2>&1
      launchctl load  "$plist" >/dev/null 2>&1
      grn "  scheduled ($when) — $plist"
      # $SNARE_ROOT under a TCC-protected folder cannot be read by a launchd
      # agent; say so now rather than letting it fail silently at 09:00.
      case "$SNARE_ROOT" in
        "$HOME/Desktop"/*|"$HOME/Documents"/*|"$HOME/Downloads"/*)
          echo
          ylw "  WARNING: snare lives under a protected folder:"
          ylw "    $SNARE_ROOT"
          ylw "  macOS blocks background agents from reading Desktop, Documents"
          ylw "  and Downloads, so this timer will fail. Move the checkout:"
          dim  "    mv \"$SNARE_ROOT\" ~/snare && cd ~/snare && ./install.sh" ;;
      esac ;;
    linux|wsl)
      local d="$HOME/.config/systemd/user"; mkdir -p "$d"
      cat > "$d/snare-report.service" <<UNIT
[Unit]
Description=snare scheduled report
[Service]
Type=oneshot
ExecStart=/bin/bash $self report --quiet --notify
UNIT
      local oncal="*-*-* 09:00:00"
      [ "$when" = weekly ] && oncal="Mon *-*-* 09:00:00"
      cat > "$d/snare-report.timer" <<UNIT
[Unit]
Description=snare scheduled report ($when)
[Timer]
OnCalendar=$oncal
Persistent=true
[Install]
WantedBy=timers.target
UNIT
      systemctl --user daemon-reload >/dev/null 2>&1
      systemctl --user enable --now snare-report.timer >/dev/null 2>&1 \
        && grn "  scheduled ($when) — systemd user timer" \
        || { red "  could not enable the timer"; return 1; } ;;
    *) die "scheduling is not supported on this platform; run 'snare report' from your own cron" ;;
  esac
  echo; dim "  reports: $SNARE_REPORTS"
  dim "  remove:  snare schedule uninstall"
}

_sched_uninstall(){
  case "$SNARE_OS" in
    macos)
      local plist="$HOME/Library/LaunchAgents/$_sched_label.plist"
      launchctl unload "$plist" >/dev/null 2>&1
      rm -f "$plist" && grn "  removed" ;;
    linux|wsl)
      systemctl --user disable --now snare-report.timer >/dev/null 2>&1
      rm -f "$HOME/.config/systemd/user/snare-report."{service,timer}
      systemctl --user daemon-reload >/dev/null 2>&1
      grn "  removed" ;;
  esac
}

_sched_status(){
  case "$SNARE_OS" in
    macos)
      launchctl list 2>/dev/null | grep -q "$_sched_label" \
        && grn "  scheduled report: installed" || ylw "  scheduled report: not installed" ;;
    linux|wsl)
      systemctl --user is-enabled snare-report.timer >/dev/null 2>&1 \
        && grn "  scheduled report: installed" || ylw "  scheduled report: not installed" ;;
  esac
  local n; n="$(ls -1 "$SNARE_REPORTS"/report-*.txt 2>/dev/null | wc -l | tr -d ' ')"
  echo "  reports on disk: ${n:-0}  ($SNARE_REPORTS)"
  local last; last="$(ls -1t "$SNARE_REPORTS"/report-*.txt 2>/dev/null | head -1)"
  [ -n "$last" ] && dim "  most recent: $last"
}
