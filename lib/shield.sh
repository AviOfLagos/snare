# shellcheck shell=bash
# shield.sh — scan before a package manager runs anything. Closes #18.
#
# The hook stops a payload leaving; the shield stops one running. Both known
# execution routes fire without you typing anything malicious, so a check that
# runs BEFORE npm/next does means the payload never gets its trigger.

SHIELD_BEGIN="# >>> snare shield >>>"
SHIELD_END="# <<< snare shield <<<"

# Fast, bounded check of one directory. Deliberately NOT a full scan: this
# runs before every npm install, so it reads config files, tasks.json and
# asset magic bytes only — no git history, no whole-tree grep.
# 0 = looks fine, 1 = something found.
cmd_shield_check(){
  local dir="${1:-$PWD}" quiet=0 found=0
  [ "${2:-}" = "--quiet" ] && quiet=1
  [ -d "$dir" ] || return 0

  local f
  # 1. build configs and any dotfile-driven config: code hidden past whitespace
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if grep -qE '[^[:space:]][[:space:]]{50,}[^[:space:]]' "$f" 2>/dev/null; then
      [ "$quiet" = 0 ] && red "  [!] $f — code hidden past a run of whitespace"
      found=1
    fi
  done < <(find "$dir" -maxdepth 3 \
             \( -name '*.config.js' -o -name '*.config.mjs' -o -name '*.config.cjs' \
                -o -name '*.config.ts' -o -name 'package.json' \) \
             -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -40)

  # 2. editor auto-execution
  if [ -f "$dir/.vscode/tasks.json" ] && grep -q folderOpen "$dir/.vscode/tasks.json" 2>/dev/null; then
    [ "$quiet" = 0 ] && red "  [!] .vscode/tasks.json uses runOn:folderOpen — executes on opening the folder"
    found=1
  fi

  # 3. assets that are not the asset they claim to be
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    case "$(head -c 4 "$f" 2>/dev/null | xxd -p 2>/dev/null)" in
      774f4632|774f4646|00010000|4f54544f|74727565) ;;
      *) [ "$quiet" = 0 ] && red "  [!] $f — not a real font (no valid magic bytes)"; found=1 ;;
    esac
  done < <(find "$dir" -maxdepth 4 \( -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' -o -name '*.otf' \) \
             -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -20)

  return $found
}

cmd_shield(){
  local sub="${1:-status}"; shift || true
  case "$sub" in
    install)   _shield_install "$@" ;;
    uninstall) _shield_uninstall ;;
    status)    _shield_status ;;
    check)     cmd_shield_check "${1:-$PWD}" ;;
    print)     _shield_snippet ;;
    *) echo "usage: snare shield [install|uninstall|status|check|print]" ;;
  esac
}

_shield_snippet(){
  cat <<SNIPPET
$SHIELD_BEGIN
# Scans the working directory before a package manager can execute anything.
# Bypass once:  SNARE_SKIP_SHIELD=1 npm install
# Remove:       snare shield uninstall
_snare_shield_guard() {
  local _tool="\$1"; shift
  # Never interfere with CI or an explicit bypass. Do NOT gate on a tty:
  # "npm install > log 2>&1" is not a tty and must still be protected. Scripts
  # are unaffected anyway, because rc files only load in interactive shells.
  if [ -n "\$SNARE_SKIP_SHIELD" ] || [ -n "\$CI" ]; then
    command "\$_tool" "\$@"; return \$?
  fi
  if command -v snare >/dev/null 2>&1; then
    if ! snare shield check . >/dev/null 2>&1; then
      printf '\\033[31m\\n  snare: this directory carries a hidden payload.\\033[0m\\n' >&2
      snare shield check . >&2
      printf '\\033[2m  refusing to run: %s %s\\033[0m\\n' "\$_tool" "\$*" >&2
      printf '\\033[2m  inspect it, or run anyway with: SNARE_SKIP_SHIELD=1 %s %s\\033[0m\\n\\n' "\$_tool" "\$*" >&2
      return 1
    fi
  fi
  command "\$_tool" "\$@"
}
npm()  { _snare_shield_guard npm  "\$@"; }
pnpm() { _snare_shield_guard pnpm "\$@"; }
yarn() { _snare_shield_guard yarn "\$@"; }
bun()  { _snare_shield_guard bun  "\$@"; }
npx()  { _snare_shield_guard npx  "\$@"; }

# git clone is safe in itself; the danger is what you do next. Scan the fresh
# clone and say so before you cd into it.
git() {
  if [ "\$1" = clone ] && [ -z "\$SNARE_SKIP_SHIELD" ] && [ -z "\$CI" ]; then
    command git "\$@" || return \$?
    local _d
    for _d in "\$@"; do :; done
    [ -d "\$_d" ] || _d="\$(basename "\${*: -1}" .git)"
    if [ -d "\$_d" ] && command -v snare >/dev/null 2>&1; then
      if ! snare shield check "\$_d" >/dev/null 2>&1; then
        printf '\\033[31m\\n  snare: the repository you just cloned carries a hidden payload.\\033[0m\\n' >&2
        snare shield check "\$_d" >&2
        printf '\\033[2m  do NOT open it in an editor or run a build in it.\\033[0m\\n\\n' >&2
      fi
    fi
    return 0
  fi
  command git "\$@"
}
$SHIELD_END
SNIPPET
}

_shield_rc(){
  # Where to write: the profile the user's shell actually reads.
  case "$(basename "${SHELL:-/bin/bash}")" in
    zsh)  printf '%s' "${ZDOTDIR:-$HOME}/.zshrc" ;;
    bash) [ -f "$HOME/.bashrc" ] && printf '%s' "$HOME/.bashrc" || printf '%s' "$HOME/.bash_profile" ;;
    *)    printf '%s' "$HOME/.profile" ;;
  esac
}

_shield_install(){
  local rc; rc="$(_shield_rc)"
  touch "$rc" 2>/dev/null || die "cannot write $rc"
  if grep -qF "$SHIELD_BEGIN" "$rc" 2>/dev/null; then
    # An installed block from an older snare can be silently WRONG — an early
    # version gated on [ -t 1 ], so "npm install > log 2>&1" skipped the check
    # entirely. Refusing to touch it left people believing they were protected.
    # Compare what is installed against what we would write, and refresh it.
    local cur new
    cur="$(sed -n "/^${SHIELD_BEGIN}\$/,/^${SHIELD_END}\$/p" "$rc" 2>/dev/null)"
    new="$(_shield_snippet)"
    if [ "$cur" = "$new" ]; then
      grn "  already installed and up to date ($rc)"
      return 0
    fi
    ylw "  an older shield is installed — refreshing it"
    cp "$rc" "$rc.snare-backup" 2>/dev/null
    _shield_uninstall >/dev/null 2>&1
    { echo; _shield_snippet; } >> "$rc"
    grn "  updated in $rc"
    dim "  backup: $rc.snare-backup"
    dim "  Takes effect in new shells, or run:  source $rc"
    return 0
  fi
  cp "$rc" "$rc.snare-backup" 2>/dev/null
  { echo; _shield_snippet; } >> "$rc"
  grn "  installed in $rc"
  dim "  backup: $rc.snare-backup"
  echo
  echo "  Wraps: npm, pnpm, yarn, bun, npx, git clone"
  dim "  Takes effect in new shells, or run:  source $rc"
  echo
  ylw "  Honest limits:"
  dim "    - shell only: it cannot see VS Code's own folderOpen task (that is the guard)"
  dim "    - anyone can bypass with 'command npm' or SNARE_SKIP_SHIELD=1"
  dim "    - it is a seatbelt, not a sandbox"
}

_shield_uninstall(){
  local rc; rc="$(_shield_rc)"
  if ! grep -qF "$SHIELD_BEGIN" "$rc" 2>/dev/null; then
    ylw "  not installed in $rc"; return 0
  fi
  # Remove exactly the delimited block, nothing else.
  python3 - "$rc" "$SHIELD_BEGIN" "$SHIELD_END" <<'PY'
import sys
rc, begin, end = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(rc).read().split('\n')
out, skip = [], False
for line in lines:
    if line.strip() == begin.strip():
        # install prepends one blank line; drop it so uninstall restores the
        # file byte-for-byte rather than leaving a growing gap behind.
        if out and out[-1].strip() == '': out.pop()
        skip = True; continue
    if line.strip() == end.strip():   skip = False; continue
    if not skip: out.append(line)
open(rc, 'w').write('\n'.join(out))
PY
  grn "  removed from $rc"
  dim "  takes effect in new shells"
}

_shield_status(){
  local rc; rc="$(_shield_rc)"
  if grep -qF "$SHIELD_BEGIN" "$rc" 2>/dev/null; then
    grn "  shield: installed in $rc"
    case "$(type npm 2>/dev/null | head -1)" in
      *function*) grn "  active in this shell" ;;
      *) ylw "  installed but not active in this shell — run: source $rc" ;;
    esac
  else
    ylw "  shield: not installed (snare shield install)"
  fi
}
