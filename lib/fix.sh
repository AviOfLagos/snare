# shellcheck shell=bash
# fix.sh — remove the malware from a GitHub repo. Dry run unless told otherwise.

# --------------------------------------------------------------- payload core
# ONE definition of what a payload is and how to take it out, shared by tip
# cleaning and history purging. Those two used to carry separate copies that
# had drifted apart, and only one of them was ever reached.
_fix_strip_core(){
  cat <<'PY'
import re

# A. The documented signature: real code, a long run of whitespace, then the
#    payload appended to the SAME line, so the file looks untouched in an
#    editor and the diff reads as a whitespace change.
LINE = re.compile(rb'^(.*?\S)[ \t]{50,}(\S.*)$')
# B. The same payload pushed onto a line of its own — the whitespace run ends
#    at a newline. Rule A cannot see that: there is no code in front of the run.
ONLY = re.compile(rb'^[ \t]*\S')
# What identifies the appended half as code rather than a trailing comment.
# Variants are minified and share no strings, so this is structural on purpose.
OBF  = re.compile(rb'_0x[0-9a-f]{4,}|\\u00[0-9a-fA-F]{2}|eval\(|atob\(|new URL\('
                  rb'|require\(["\']node:|child_process|\}\)\(\);?\s*$')
# Hard campaign markers, matched lowercase. Never the primary test — an
# obfuscated variant contains none of them — but near enough to zero false
# positives to justify dropping a whole line rather than only a line's tail.
MARK = re.compile(rb'0xa322e5f3d311d3080e6f0121063e9adc2490ef1a'
                  rb'|eth\.blockscout\.com'
                  rb'|/0x/cl[bs]|/0x/ls'
                  rb'|q4fzkxx'
                  rb"|global\.i\s*=\s*['\"]a8-")

def _payload(seg):
    return bool(OBF.search(seg) or MARK.search(seg.lower()))

def _dense(ln):
    """Minified-shaped. Prose is mostly spaces; an appended payload is not."""
    return ln.count(b' ') * 10 < len(ln)

def clean(data):
    """Strip the payload and KEEP the file. Returns (data, changed)."""
    out, changed = [], False
    for ln in data.split(b'\n'):
        m = LINE.match(ln)
        if m and _payload(m.group(2)):
            out.append(m.group(1)); changed = True; continue
        # A line that is payload and nothing else: drop it whole. Dropping a
        # WHOLE line is destructive, so the gate is deliberately narrow — long,
        # minified-shaped, a hard campaign marker AND obfuscated code. Requiring
        # only a marker deleted every line that legitimately quotes one,
        # including this tool's own guard pattern and its write-ups.
        if (len(ln) > 200 and ONLY.match(ln) and _dense(ln)
                and MARK.search(ln.lower()) and OBF.search(ln)):
            changed = True; continue
        out.append(ln)
    return b'\n'.join(out), changed

def residue(data):
    """Hard markers still present after cleaning: the file IS the dropper."""
    return bool(MARK.search(data.lower()))
PY
}

# $1 = file | blob | verify — the core plus one wrapper around it.
_fix_strip_prog(){
  _fix_strip_core
  case "$1" in
    file) cat <<'PY'
import sys
p = sys.argv[1]
data = open(p, 'rb').read()
new, changed = clean(data)
if not changed:
    print("RESIDUE" if residue(data) else "NONE")
elif not new.strip():
    print("EMPTY")                       # the file WAS the payload
else:
    open(p, 'wb').write(new)
    print("RESIDUE" if residue(new) else "STRIPPED")
PY
;;
    blob) cat <<'PY'
new, changed = clean(blob.data)
if changed:
    blob.data = new
PY
;;
    verify) cat <<'PY'
# Re-read every blob and ask the SAME cleaner whether anything is left. The old
# check grepped for one hardcoded marker, so an obfuscated variant verified
# clean after stripping nothing at all — and then got force-pushed.
import subprocess, sys

def read_exact(f, n):
    buf = b''
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

ids = [l.strip() for l in sys.stdin if l.strip()]
if not ids:
    print(0); raise SystemExit
p = subprocess.Popen(['git', 'cat-file', '--batch'],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)
left = 0
for oid in ids:
    p.stdin.write((oid + '\n').encode()); p.stdin.flush()
    header = p.stdout.readline().split()
    if len(header) < 3:
        continue
    data = read_exact(p.stdout, int(header[2]))
    p.stdout.read(1)                      # the trailing newline
    if clean(data)[1]:
        left += 1
p.stdin.close(); p.wait()
print(left)
PY
;;
  esac
}

# .vscode/tasks.json is a file a project may genuinely use. Remove the task
# that runs on folderOpen and keep the rest, rather than deleting someone's
# build and test tasks along with the malicious one.
_fix_tasks_prog(){
  cat <<'PY'
import json, sys
p = sys.argv[1]
try:
    d = json.loads(open(p, 'rb').read())
    tasks = d["tasks"]
    if not isinstance(tasks, list):
        raise ValueError
except Exception:
    print("UNPARSEABLE"); raise SystemExit
kept, removed = [], []
for t in tasks:
    ro = t.get("runOptions") or {} if isinstance(t, dict) else {}
    if str(ro.get("runOn", "")).lower() == "folderopen":
        removed.append(str(t.get("label", "(unlabelled)")))
    else:
        kept.append(t)
if not removed:
    print("NONE")
elif kept:
    d["tasks"] = kept
    open(p, 'w').write(json.dumps(d, indent=2) + "\n")
    print("STRIPPED\t" + ", ".join(removed))
else:
    print("EMPTY\t" + ", ".join(removed))
PY
}

# Files a project cannot build without. snare will strip these and warn about
# these; it will not delete them. Losing a build config to the remediation is
# its own outage, and an outage is not a fix.
_fix_is_needed(){
  case "$(basename "$1")" in
    package.json|package-lock.json|pnpm-lock.yaml|yarn.lock|tasks.json) return 0 ;;
    tsconfig*.json) return 0 ;;
    *.config.js|*.config.mjs|*.config.cjs|*.config.ts|*.config.mts|*.config.cts|*.config.json) return 0 ;;
  esac
  return 1
}

# Clean the tree checked out in $PWD. Prints one line per action, stages every
# change, and returns 0 when it changed something.
#
# The ORDER here is the whole point. Stripping runs FIRST. The delete pass
# removes files matching an IOC string — and a payload appended to
# postcss.config.mjs IS an IOC string, so the config was deleted before the
# strip pass could see it, and the project lost the file it builds with.
_fix_clean_tree(){
  local br="$1" pattern="$2" changed=0 f verdict cand

  # snare's own source legitimately contains every IOC string and a literal
  # payload sample in its write-ups — it is the detector. scan and hook already
  # skip it; fix must too, or remediating a fork of snare eats the guard's own
  # kill pattern.
  local SELF=0
  [ -f .snare-tool ] && { SELF=1; dim "  [$br] (snare's own source tree — its own detection files are skipped)"; }

  # ---- 1. editor auto-execution, surgically ------------------------------
  if [ -f .vscode/tasks.json ] && grep -q folderOpen .vscode/tasks.json 2>/dev/null; then
    verdict="$(python3 -c "$(_fix_tasks_prog)" .vscode/tasks.json 2>/dev/null)"
    case "${verdict%%$'\t'*}" in
      STRIPPED)
        git add .vscode/tasks.json 2>/dev/null
        echo "  [$br] .vscode/tasks.json: removed the folderOpen task (${verdict#*$'\t'}), kept the others"
        changed=1 ;;
      NONE)
        ylw "  [$br] .vscode/tasks.json mentions folderOpen but defines no such task — left alone, read it" ;;
      *)
        git rm -q -f .vscode/tasks.json 2>/dev/null \
          && { echo "  [$br] removed .vscode/tasks.json (nothing legitimate left in it)"; changed=1; } ;;
    esac
  fi

  # ---- 2. payload and nothing else: delete ---------------------------------
  # These are found by NAME and by MAGIC BYTES, not by content, so they need
  # their own passes — a dropper wearing a .woff2 extension matches no IOC
  # string, and a file called setup_bun.js need not mention its own name.
  while IFS= read -r f; do
    [ -z "$f" ] || [ ! -f "$f" ] && continue
    git rm -q -f "$f" 2>/dev/null \
      && { echo "  [$br] removed ${f#./} (known worm artifact)"; changed=1; }
  done < <(find . \( -name setup_bun.js -o -name bun_environment.js \
                  -o -name 'shai-hulud*' -o -name 'truffleSecrets*' \) \
             -not -path './.git/*' -not -path '*/node_modules/*' 2>/dev/null)

  while IFS= read -r f; do
    [ -z "$f" ] || [ ! -f "$f" ] && continue
    is_font "$f" && continue
    git rm -q -f "$f" 2>/dev/null \
      && { echo "  [$br] removed ${f#./} (not a real font — a payload wearing an asset extension)"; changed=1; }
  done < <(find . \( -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' -o -name '*.otf' \) \
             -not -path './.git/*' -not -path '*/node_modules/*' 2>/dev/null)

  # ---- 3. every file that trips either content signature -------------------
  cand="$(mktemp "${TMPDIR:-/tmp}/snarefix.XXXXXX")" || return 1
  {
    grep -rlE "$pattern" . --exclude-dir=.git --exclude-dir=node_modules 2>/dev/null
    grep -rlE '[^[:space:]][[:space:]]{50,}[^[:space:]]' . \
      --exclude-dir=.git --exclude-dir=node_modules 2>/dev/null
  } | sed 's|^\./||' | sort -u > "$cand"

  while IFS= read -r f; do
    [ -z "$f" ] || [ ! -f "$f" ] && continue
    case "$f" in .vscode/tasks.json) continue ;; esac
    if [ "$SELF" = 1 ]; then
      case "$f" in
        lib/*|bin/*|docs/*|promo/*|iocs.txt|README.md|CHANGELOG.md|.github/*) continue ;;
      esac
    fi

    # Strip it, and keep the file if anything real
    #     survives. This is the case the old code never reached.
    verdict="$(python3 -c "$(_fix_strip_prog file)" "$f" 2>/dev/null)"
    case "$verdict" in
      STRIPPED)
        git add "$f" 2>/dev/null
        grn "  [$br] stripped the payload from $f (file kept)"; changed=1 ;;
      EMPTY)
        git rm -q -f "$f" 2>/dev/null \
          && { echo "  [$br] removed $f (the file was nothing but payload)"; changed=1; } ;;
      RESIDUE)
        if _fix_is_needed "$f"; then
          git add "$f" 2>/dev/null
          red "  [$br] $f still carries campaign markers after stripping — NOT deleted"
          dim "        the project needs this file; read it yourself before you merge"
          changed=1
        else
          git rm -q -f "$f" 2>/dev/null \
            && { echo "  [$br] removed $f (dropper: the payload is the whole file)"; changed=1; }
        fi ;;
      *)
        # NONE: nothing was structurally strippable.
        if ! grep -qE "$pattern" "$f" 2>/dev/null; then
          # Only the whitespace heuristic fired and the tail is not payload-
          # shaped. Never delete a file on that alone — say so instead.
          ylw "  [$br] $f has a long whitespace run but no payload signature — left alone, read it"
        elif _fix_is_needed "$f"; then
          ylw "  [$br] $f matches an IOC but nothing could be stripped — left in place, read it"
        else
          git rm -q -f "$f" 2>/dev/null \
            && { echo "  [$br] removed $f (matches a known IOC)"; changed=1; }
        fi ;;
    esac
  done < "$cand"
  rm -f "$cand"

  [ "$changed" = 1 ] && return 0
  return 1
}

# snare fix --all — remediate every repo the last `scan github` flagged.
# Dry-run by default; --push/--purge-history require an interactive confirm,
# because this can force-push to repositories other people depend on.
cmd_fix_all(){
  local flagged="$SNARE_LOGS/flagged.txt"
  [ -s "$flagged" ] || die "no flagged repos — run: snare scan github"

  local n; n="$(grep -c . "$flagged" | tr -d ' ')"
  hdr "snare fix --all"
  echo "  $n repo(s) flagged by the last scan:"
  sed 's/^/      /' "$flagged"

  local push=0 purge=0 yes=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --push) push=1 ;;
      --purge-history) purge=1 ;;
      --yes) yes=1 ;;
    esac; shift
  done

  if [ "$push" = 0 ] && [ "$purge" = 0 ]; then
    echo; ylw "  dry run — nothing will be changed or pushed."
    dim "  to actually remediate:  snare fix --all --push"
    dim "  to erase from history:  snare fix --all --purge-history --push"
  else
    echo
    red "  This will modify ${n} repository(ies) on GitHub."
    [ "$purge" = 1 ] && red "  --purge-history REWRITES HISTORY: every SHA changes and every"
    [ "$purge" = 1 ] && red "  collaborator must re-clone. Forks and PR refs keep the old objects."
    if [ "$yes" = 0 ]; then
      if [ ! -t 0 ]; then
        die "refusing to run non-interactively without --yes"
      fi
      printf '%s' "  Type the number of repos to confirm ($n): "
      local ans; read -r ans
      [ "$ans" = "$n" ] || die "confirmation did not match — aborted"
    fi
  fi

  local r ok=0 bad=0 found=0 dry=0 rc
  [ "$push" = 0 ] && [ "$purge" = 0 ] && dry=1
  while IFS= read -r r; do
    [ -z "$r" ] && continue
    hdr "=== $r ==="
    ( cmd_fix "$r" ${push:+$([ "$push" = 1 ] && echo --push)} \
                   ${purge:+$([ "$purge" = 1 ] && echo --purge-history)} )
    rc=$?
    case "$rc" in
      0) ok=$((ok+1)) ;;
      3) found=$((found+1)) ;;
      *) bad=$((bad+1)); red "  FAILED: $r" ;;
    esac
  done < "$flagged"

  hdr "RESULT"
  if [ "$dry" = 1 ]; then
    echo "  carrying a payload: $found    already clean: $ok    unreadable: $bad"
    echo
    dim "  Nothing was changed. To act on this:"
    dim "      snare fix --all --push                    clean branch tips"
    dim "      snare fix --all --purge-history --push    erase it from all history"
  else
    echo "  cleaned: $ok    failed: $bad"
  fi
  [ "$bad" -gt 0 ] && return 1
  return 0
}

# snare fix --pick / --owner — choose organisations, scan them, then remediate
# what was found, in one pass.
#
# The destructive flags stay on the command line rather than hiding inside a new
# verb: force-pushing rewritten history across an organisation should be legible
# in your shell history, not something a friendly-sounding command did for you.
cmd_fix_pick(){
  require_gh
  local owners="" pick=0 allacct=0 push=0 purge=0 yes=0 allbr=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --pick|--select)  pick=1 ;;
      --owner)          owners="${2:-}"; shift ;;
      --all-accounts)   allacct=1 ;;
      --push)           push=1 ;;
      --purge-history)  purge=1 ;;
      --yes)            yes=1 ;;
      --all-branches)   allbr=1 ;;
      *) red "unknown flag: $1"
         echo "  usage: snare fix --pick [--all-branches] [--purge-history] [--push] [--yes]"
         echo "         snare fix --owner a,b [--purge-history] [--push]"
         return 2 ;;
    esac; shift
  done

  # git-filter-repo is needed for EVERY repository in a purge. Discovering that
  # after a twenty-minute scan of an organisation wastes the whole run, so ask
  # before anything happens.
  if [ "$purge" = 1 ] && ! command -v git-filter-repo >/dev/null 2>&1; then
    red "git-filter-repo is required for --purge-history, and it is not installed."
    case "$SNARE_OS" in
      macos)     echo "  brew install git-filter-repo" ;;
      linux|wsl) echo "  pipx install git-filter-repo    (or: sudo apt install git-filter-repo)" ;;
      windows)   echo "  pip install git-filter-repo" ;;
      *)         echo "  https://github.com/newren/git-filter-repo" ;;
    esac
    return 2
  fi

  if [ "$pick" = 1 ]; then
    if [ ! -t 0 ] || [ ! -t 1 ] || [ -n "${CI:-}" ]; then
      red "--pick needs a terminal."
      echo "  list what is reachable:  snare scan orgs"
      echo "  then name them:          snare fix --owner acme,other --purge-history --push"
      return 2
    fi
    owners="$(_scan_pick_owners "$allacct")" || return 2
  fi
  if [ -z "$owners" ]; then
    ylw "  nothing selected — nothing scanned, nothing changed"
    return 0
  fi

  hdr "1. Scan the owners you chose"
  dim "  read-only — nothing is changed in this step"
  local sargs=(--owner "$(printf '%s' "$owners" | tr '\n' ',')")
  [ "$allbr" = 1 ] && sargs+=(--all-branches)
  cmd_scan_github "${sargs[@]}"

  local flagged="$SNARE_LOGS/flagged.txt"
  if [ ! -s "$flagged" ]; then
    echo
    grn "  Nothing flagged in the owner(s) you chose — nothing to fix."
    dim "  That is branch tips only. A payload committed and later deleted still"
    dim "  lives in history: snare scan repo <clone> is the thorough check."
    return 0
  fi

  hdr "2. Remediate what was found"
  if [ "$push" = 1 ] || [ "$purge" = 1 ]; then
    # snare's own ordering, at the moment it matters most. Not a wall — a
    # blocked user abandons the clean-up — but this is the last point before
    # anything is written to somebody else's repository.
    ylw "  Before you push: have you rotated your credentials?"
    dim  "  Stealing them is what this family is FOR. Removing the payload does not"
    dim  "  un-steal a token, and cleaning repositories from a machine that is still"
    dim  "  infected just re-injects into the ones you have cleaned."
    dim  "      snare rotate        what to revoke, in what order"
    dim  "      snare doctor        is this machine clean?"
    echo
  fi

  local fargs=()
  [ "$push" = 1 ]  && fargs+=(--push)
  [ "$purge" = 1 ] && fargs+=(--purge-history)
  [ "$yes" = 1 ]   && fargs+=(--yes)
  cmd_fix_all ${fargs[@]+"${fargs[@]}"}
}


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
    # Whitespace-hidden payload in a build config matches no IOC string.
    local w; w="$(git grep -lE '[^[:space:]][[:space:]]{50,}[^[:space:]]' "$ref" -- \
                  '*.config.js' '*.config.mjs' '*.config.cjs' '*.config.ts' 2>/dev/null | head -3)"
    [ -n "$w" ] && { red "  [$br] hidden payload past whitespace:"; echo "$w" | sed 's/^/      /'; found=1; }
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
    dim "  Build configs and package.json are stripped and kept, never deleted."
    # 3, not 1: "found it, changed nothing" is the successful outcome of a dry
    # run. Sharing an exit code with a real failure made `fix --all` report
    # "succeeded: 0  failed: 5" for five repositories it had read correctly.
    return 3
  fi

  if [ "$purge" = 1 ]; then
    hdr "4. Purge from all history"
    need git-filter-repo
    git filter-repo --force --blob-callback "$(_fix_strip_prog blob)" 2>&1 | tail -4
    # Verify by re-running the same cleaner over every blob, not by grepping
    # for one marker string a variant need not contain.
    local left
    left="$(git rev-list --objects --all 2>/dev/null | awk '{print $1}' \
            | git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize)' 2>/dev/null \
            | awk '$2=="blob" && $3<400000 {print $1}' \
            | python3 -c "$(_fix_strip_prog verify)" 2>/dev/null)"
    echo "  blobs still carrying a hidden payload: ${left:-unknown}"
    [ "${left:-1}" != "0" ] && die "purge incomplete — not pushing"
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
    if _fix_clean_tree "$br" "$pattern"; then
      git commit -q -m "security: remove supply-chain malware dropper

Found by snare. Files the project needs (build configs, package.json) were
stripped of the payload and kept; files that were payload only were removed.
See the security issue on this repository for detail."
      [ "$push" = 1 ] && GIT_TERMINAL_PROMPT=0 git push -q origin "$br" && grn "  [$br] pushed"
    fi
  done
  [ "$push" = 0 ] && ylw "  not pushed (add --push)"
  ylw "  Tip-only cleaning leaves the payload in history — use --purge-history for a full fix."
}
