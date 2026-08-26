# shellcheck shell=bash
# hook.sh — stop the payload leaving the machine. Closes #9.
#
# This family injects into commits from an already-infected developer machine,
# so the payload is pushed before anyone scans a repo. Cleaning repositories
# afterwards treats the symptom; refusing the push treats the cause.

cmd_hook(){
  local sub="${1:-status}"; shift || true
  case "$sub" in
    install)   _hook_install "$@" ;;
    uninstall) _hook_uninstall "$@" ;;
    status)    _hook_status "$@" ;;
    run)       _hook_run "$@" ;;
    *) echo "usage: snare hook [install|uninstall|status|run] [path]" ;;
  esac
}

# The check a hook performs. Scans what is about to leave: staged content for
# pre-commit, the working tree for pre-push. Exits non-zero to block.
_hook_run(){
  local mode="${1:-pre-push}"
  local pattern; pattern="$(ioc_pattern)"
  local bad=0 f

  # Files under consideration: staged for commit, else tracked files.
  local list
  if [ "$mode" = "pre-commit" ]; then
    list="$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)"
  else
    list="$(git ls-files 2>/dev/null)"
  fi

  while IFS= read -r f; do
    [ -z "$f" ] || [ ! -f "$f" ] && continue
    case "$f" in */node_modules/*|node_modules/*) continue ;; esac

    # 1. code hidden past a run of whitespace — the signature that matters
    if grep -qE '[^[:space:]][[:space:]]{50,}[^[:space:]]' "$f" 2>/dev/null; then
      red "  [blocked] $f — code hidden past a run of whitespace"
      bad=1
    fi
    # 2. known IOC strings
    if grep -qE "$pattern" "$f" 2>/dev/null; then
      red "  [blocked] $f — matches a known IOC"
      bad=1
    fi
    # 3. an asset that is not the asset it claims to be
    case "$f" in
      *.woff2|*.woff|*.ttf|*.otf)
        case "$(head -c 4 "$f" 2>/dev/null | xxd -p 2>/dev/null)" in
          774f4632|774f4646|00010000|4f54544f|74727565) ;;
          *) red "  [blocked] $f — not a real font (no valid magic bytes)"; bad=1 ;;
        esac ;;
    esac
  done <<< "$list"

  # 4. editor auto-execution
  if [ -f .vscode/tasks.json ] && grep -q folderOpen .vscode/tasks.json 2>/dev/null; then
    red "  [blocked] .vscode/tasks.json uses runOn:folderOpen"
    bad=1
  fi

  # 5. the machine itself. A clean repo pushed from an infected machine is how
  #    this spreads: the loader injects into the commit on its way out. Refuse
  #    to push at all while something is live, whatever the repo looks like.
  if ! guard_scan_once >/dev/null 2>&1; then
    echo
    red "  [blocked] THIS MACHINE has a live detection."
    red "  A clean repo pushed from an infected machine can still carry the"
    red "  payload — the loader injects on the way out."
    dim "  see:  $SNARE_LOGS/guard.log"
    dim "  then: snare doctor    and    snare guard scan"
    bad=1
  fi

  if [ "$bad" = 1 ]; then
    echo
    red "  snare blocked this $mode."
    dim "  Inspect the files above. If you are certain they are safe:"
    dim "      git $([ "$mode" = pre-commit ] && echo commit || echo push) --no-verify"
    return 1
  fi
  return 0
}

_hook_install(){
  local dir="${1:-$PWD}" both=0
  [ "${1:-}" = "--with-pre-commit" ] && { both=1; dir="${2:-$PWD}"; }
  git -C "$dir" rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository: $dir"
  local hd; hd="$(git -C "$dir" rev-parse --git-path hooks 2>/dev/null)"
  hd="$(cd "$dir" && cd "$hd" 2>/dev/null && pwd)" || die "cannot locate hooks dir"
  local self="$SNARE_ROOT/bin/snare"

  _hook_write "$hd/pre-push" pre-push "$self"
  grn "  installed: $hd/pre-push"
  if [ "$both" = 1 ]; then
    _hook_write "$hd/pre-commit" pre-commit "$self"
    grn "  installed: $hd/pre-commit"
  fi
  echo; dim "  bypass once:  git push --no-verify"
  dim "  remove:       snare hook uninstall"
}

_hook_write(){
  local path="$1" mode="$2" self="$3"
  # Preserve an existing non-snare hook rather than destroying someone's setup.
  if [ -f "$path" ] && ! grep -q 'snare hook run' "$path" 2>/dev/null; then
    mv "$path" "$path.pre-snare"
    ylw "  existing hook preserved: $path.pre-snare"
  fi
  cat > "$path" <<HOOK
#!/usr/bin/env bash
# installed by snare — blocks a $mode carrying a hidden payload
[ -n "\$SNARE_SKIP_HOOK" ] && exit 0
if [ -x "$self" ]; then
  "$self" hook run $mode || exit 1
fi
[ -x "\$(dirname "\$0")/$mode.pre-snare" ] && exec "\$(dirname "\$0")/$mode.pre-snare" "\$@"
exit 0
HOOK
  chmod +x "$path"
}

_hook_uninstall(){
  local dir="${1:-$PWD}"
  local hd; hd="$(git -C "$dir" rev-parse --git-path hooks 2>/dev/null)"
  hd="$(cd "$dir" && cd "$hd" 2>/dev/null && pwd)" || die "cannot locate hooks dir"
  local h
  for h in pre-push pre-commit; do
    if [ -f "$hd/$h" ] && grep -q 'snare hook run' "$hd/$h" 2>/dev/null; then
      rm -f "$hd/$h"
      grn "  removed: $hd/$h"
      [ -f "$hd/$h.pre-snare" ] && { mv "$hd/$h.pre-snare" "$hd/$h"; dim "  restored your previous $h"; }
    fi
  done
}

_hook_status(){
  local dir="${1:-$PWD}"
  local hd; hd="$(git -C "$dir" rev-parse --git-path hooks 2>/dev/null)"
  hd="$(cd "$dir" && cd "$hd" 2>/dev/null && pwd)" || { ylw "  not a git repository"; return 0; }
  local h found=0
  for h in pre-push pre-commit; do
    if [ -f "$hd/$h" ] && grep -q 'snare hook run' "$hd/$h" 2>/dev/null; then
      grn "  $h: installed"; found=1
    fi
  done
  [ "$found" = 0 ] && ylw "  no snare hooks installed here (snare hook install)"
  return 0
}
