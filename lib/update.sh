# shellcheck shell=bash
# update.sh — keep snare current. Closes #4.
#
# Users clone snare once and never again. Four false-clean defects shipped
# this way, so an update path is a security feature, not a convenience.

# Version string of the checkout at $1 (default: SNARE_ROOT), without sourcing it.
snare_version_at(){
  local d="${1:-$SNARE_ROOT}"
  grep -m1 '^SNARE_VERSION=' "$d/bin/snare" 2>/dev/null | cut -d'"' -f2
}

# Remote HEAD version, via the raw file. Empty on any failure — never fatal.
snare_remote_version(){
  local url="https://raw.githubusercontent.com/AviOfLagos/snare/main/bin/snare"
  curl -fsSL --max-time 10 "$url" 2>/dev/null \
    | grep -m1 '^SNARE_VERSION=' | cut -d'"' -f2
}

# Cheap, quiet check used by `snare version`. Prints a nudge or nothing.
snare_update_hint(){
  local r; r="$(snare_remote_version)"
  [ -z "$r" ] && return 0
  [ "$r" = "$SNARE_VERSION" ] && return 0
  ylw "  a newer version is available: $r (you have $SNARE_VERSION)"
  dim "  run: snare update"
}

cmd_update(){
  local force=0 check=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --force) force=1 ;;
      --check) check=1 ;;
      *) red "unknown flag: $1"; return 2 ;;
    esac; shift
  done

  hdr "snare update"
  echo "  install: $SNARE_ROOT"
  echo "  version: $SNARE_VERSION"

  if [ "$check" = 1 ]; then
    local r; r="$(snare_remote_version)"
    if [ -z "$r" ]; then ylw "  could not reach GitHub"; return 1; fi
    if [ "$r" = "$SNARE_VERSION" ]; then grn "  up to date ($r)"; else
      ylw "  update available: $r"; dim "  run: snare update"; fi
    return 0
  fi

  if [ ! -d "$SNARE_ROOT/.git" ]; then
    red "  $SNARE_ROOT is not a git checkout"
    dim "  reinstall:  git clone https://github.com/AviOfLagos/snare ~/snare && cd ~/snare && ./install.sh"
    return 1
  fi

  # Refuse to discard the user's own edits unless they say so.
  local dirty; dirty="$(git -C "$SNARE_ROOT" status --porcelain 2>/dev/null)"
  if [ -n "$dirty" ] && [ "$force" = 0 ]; then
    red "  local modifications present — refusing to overwrite:"
    echo "$dirty" | sed 's/^/      /' | head -10
    dim "  keep them:     cd $SNARE_ROOT && git stash"
    dim "  discard them:  snare update --force"
    return 1
  fi

  local before; before="$(git -C "$SNARE_ROOT" rev-parse --short HEAD 2>/dev/null)"
  local branch; branch="$(git -C "$SNARE_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null)"

  echo "  fetching..."
  if ! git -C "$SNARE_ROOT" fetch --quiet origin 2>/dev/null; then
    red "  fetch failed — check your network or remote"
    return 1
  fi

  # Detached HEAD or a non-main branch: land on main rather than guessing.
  if [ "$branch" = "HEAD" ] || [ -z "$branch" ]; then
    ylw "  detached HEAD — checking out main"
    git -C "$SNARE_ROOT" checkout -q main 2>/dev/null || {
      red "  could not check out main"; return 1; }
    branch=main
  fi

  if [ "$force" = 1 ] && [ -n "$dirty" ]; then
    ylw "  discarding local modifications (--force)"
    git -C "$SNARE_ROOT" reset -q --hard "origin/$branch" 2>/dev/null
  else
    # Fast-forward only: never create a merge commit in someone's install.
    if ! git -C "$SNARE_ROOT" merge --ff-only -q "origin/$branch" 2>/dev/null; then
      red "  cannot fast-forward $branch (history diverged)"
      dim "  reset to the published version:  snare update --force"
      return 1
    fi
  fi

  local after; after="$(git -C "$SNARE_ROOT" rev-parse --short HEAD 2>/dev/null)"
  local newver; newver="$(snare_version_at "$SNARE_ROOT")"

  if [ "$before" = "$after" ]; then
    grn "  already up to date ($SNARE_VERSION, $after)"
  else
    grn "  updated: $SNARE_VERSION ($before) -> ${newver:-?} ($after)"
    echo
    dim "  changes:"
    git -C "$SNARE_ROOT" log --oneline "$before..$after" 2>/dev/null | sed 's/^/      /' | head -15
  fi

  # Keep the launcher pointing at this checkout wherever it lives.
  local bin="${SNARE_BIN:-$HOME/.local/bin}"
  if [ -e "$bin/snare" ]; then
    ln -sf "$SNARE_ROOT/bin/snare" "$bin/snare" 2>/dev/null
    chmod +x "$SNARE_ROOT/bin/snare" 2>/dev/null
    dim "  relinked $bin/snare -> $SNARE_ROOT/bin/snare"
  fi

  # Updating the checkout does not update anything snare has installed
  # elsewhere. Those copies keep running old code, and in the shield's case an
  # old copy was silently WRONG rather than merely stale — so say what needs
  # refreshing instead of leaving people to assume it was handled.
  local stale=0

  if launchctl list 2>/dev/null | grep -q com.snare.guard \
     || systemctl --user is-active snare-guard >/dev/null 2>&1; then
    echo; ylw "  the background guard is still running the previous version"
    dim "    snare guard stop && snare guard start"
    stale=1
  fi

  # Shield: compare the installed block against what we would write now.
  local rc
  case "$(basename "${SHELL:-/bin/bash}")" in
    zsh)  rc="${ZDOTDIR:-$HOME}/.zshrc" ;;
    bash) rc="$HOME/.bashrc"; [ -f "$rc" ] || rc="$HOME/.bash_profile" ;;
    *)    rc="$HOME/.profile" ;;
  esac
  if [ -f "$rc" ] && grep -qF '# >>> snare shield >>>' "$rc" 2>/dev/null; then
    local cur_block new_block
    cur_block="$(sed -n '/^# >>> snare shield >>>$/,/^# <<< snare shield <<<$/p' "$rc" 2>/dev/null)"
    new_block="$(_shield_snippet 2>/dev/null)"
    if [ "$cur_block" != "$new_block" ]; then
      [ "$stale" = 0 ] && echo
      ylw "  the installed shell shield is from an older version"
      dim "    snare shield install     (refreshes it in place)"
      stale=1
    fi
  fi

  # Hooks in this repo, if snare is being run from inside one.
  local hd
  hd="$(git rev-parse --git-path hooks 2>/dev/null)"
  if [ -n "$hd" ] && [ -d "$hd" ]; then
    local h
    for h in pre-push pre-commit; do
      if [ -f "$hd/$h" ] && ! grep -q 'snare-hook-v1' "$hd/$h" 2>/dev/null \
         && grep -qE 'snare"?[[:space:]]+hook[[:space:]]+run' "$hd/$h" 2>/dev/null; then
        [ "$stale" = 0 ] && echo
        ylw "  the $h hook in this repository is from an older version"
        dim "    snare hook install       (upgrades it in place)"
        stale=1
      fi
    done
  fi

  echo
  dim "  verify detection still works:  snare selftest"
}
