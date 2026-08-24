# shellcheck shell=bash
# fix.sh — remove the malware from a GitHub repo. Dry run unless told otherwise.

cmd_fix(){
  require_gh
  local repo="${1:-}"; shift || true
  [ -n "$repo" ] || die "usage: snare fix <owner/repo> [--push] [--purge-history]"
  local push=0 purge=0
  while [ $# -gt 0 ]; do
    case "$1" in --push) push=1 ;; --purge-history) purge=1 ;; esac; shift
  done

  local safe src stamp bundle pattern
  safe="$(echo "$repo" | tr '/' '_')"; src="$SNARE_WORK/$safe"
  stamp="$(date '+%Y%m%dT%H%M%S')"; pattern="$(ioc_pattern)"

  hdr "1. Clone"
  rm -rf "$src"
  GIT_TERMINAL_PROMPT=0 git clone --quiet --no-single-branch "https://github.com/$repo.git" "$src" \
    || die "clone failed (check access to $repo)"
  cd "$src" || die "cannot enter $src"
  git fetch --quiet --all --tags 2>/dev/null
  local me; me="$(gh_user)"
  git config user.name "$me"
  git config user.email "$(gh api user --jq '.email // empty' 2>/dev/null || echo "$me@users.noreply.github.com")"
  grn "  $(git rev-list --all --count) commits"

  hdr "2. Backup (always, before any change)"
  bundle="$SNARE_BACKUPS/${safe}-${stamp}.bundle"
  git bundle create "$bundle" --all >/dev/null 2>&1 || die "backup failed — refusing to continue"
  grn "  $bundle"
  dim "  restore with: git clone $bundle restored"

  hdr "3. Findings"
  local found=0 ref br
  for ref in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin | grep -v HEAD); do
    br="${ref#origin/}"
    git show "$ref:.vscode/tasks.json" 2>/dev/null | grep -q folderOpen \
      && { red "  [$br] .vscode/tasks.json runOn:folderOpen"; found=1; }
    local m; m="$(git grep -InE "$pattern" "$ref" -- 2>/dev/null | head -3)"
    [ -n "$m" ] && { red "  [$br] IOC content:"; echo "$m" | cut -c1-140 | sed 's/^/      /'; found=1; }
  done
  while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    local c; c="$(git log --all --oneline -S"$pat" --pickaxe-regex 2>/dev/null | head -2)"
    [ -n "$c" ] && { red "  [history] '$pat'"; echo "$c" | sed 's/^/      /'; found=1; }
  done < <(ioc_list)
  [ "$found" = 0 ] && { grn "  nothing found — repo looks clean"; return 0; }

  if [ "$push" = 0 ] && [ "$purge" = 0 ]; then
    hdr "DRY RUN — nothing changed"
    ylw "  snare fix $repo --push                    clean branch tips and push"
    ylw "  snare fix $repo --purge-history --push    also erase it from all history"
    dim "  (--purge-history rewrites shared history; every collaborator must re-clone)"
    return 1
  fi

  if [ "$purge" = 1 ]; then
    hdr "4. Purge from all history"
    need git-filter-repo
    local cb="$SNARE_WORK/.strip.py"
    cat > "$cb" <<'PY'
import re
MARK=[b'A8-3379-6',b'0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a',
      b'0xa322e5f3d311d3080e6f0121063e9adc2490ef1a',b'eth.blockscout.com']
if any(m in blob.data for m in MARK):
    m=re.search(rb'[ \t]{50,}',blob.data)          # the whitespace the payload hides behind
    if m: blob.data=blob.data[:m.start()].rstrip()+b'\n'
PY
    git filter-repo --force --blob-callback "$(cat "$cb")" 2>&1 | tail -4
    local left; left="$(git log --all --oneline -S 'A8-3379-6' --pickaxe-regex 2>/dev/null | wc -l | tr -d ' ')"
    echo "  commits still carrying the marker: $left"
    [ "$left" != "0" ] && die "purge incomplete — not pushing"
    git remote add origin "https://github.com/$repo.git" 2>/dev/null || \
      git remote set-url origin "https://github.com/$repo.git"
    if [ "$push" = 1 ]; then
      ylw "  force-pushing rewritten history (refs/heads only)"
      local r
      for r in $(git for-each-ref --format='%(refname)' refs/heads); do
        GIT_TERMINAL_PROMPT=0 git push --force origin "$r:$r" 2>&1 | tail -2
      done
      red "  Collaborators MUST re-clone. Forks, PR refs and old SHAs still hold it —"
      red "  ask GitHub Support to garbage-collect unreachable objects."
    else ylw "  rewritten locally, not pushed. Inspect: cd $src"; fi
    return 0
  fi

  hdr "4. Clean branch tips"
  for ref in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin | grep -v HEAD); do
    br="${ref#origin/}"
    git checkout -q -B "$br" "$ref" 2>/dev/null || continue
    local changed=0
    [ -f .vscode/tasks.json ] && grep -q folderOpen .vscode/tasks.json && {
      git rm -q -f .vscode/tasks.json; changed=1; echo "  [$br] removed .vscode/tasks.json"; }
    local f
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      git rm -q -f "$f" 2>/dev/null && { changed=1; echo "  [$br] removed $f"; }
    done < <(grep -rlE "$pattern" . --exclude-dir=.git 2>/dev/null | head -10)
    [ "$changed" = 1 ] && {
      git commit -q -m "security: remove supply-chain malware dropper

Found by snare. See the security issue on this repository for detail."
      [ "$push" = 1 ] && GIT_TERMINAL_PROMPT=0 git push -q origin "$br" && grn "  [$br] pushed"
    }
  done
  [ "$push" = 0 ] && ylw "  not pushed (add --push)"
  ylw "  Tip-only cleaning leaves the payload in history — use --purge-history for a full fix."
}
