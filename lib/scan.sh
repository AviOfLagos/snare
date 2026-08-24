# shellcheck shell=bash
# scan.sh — repo scanning: one local repo, or every repo you can reach.

FF=""
_hit(){ echo x >> "$FF"; red "  [!] $*"; }
_note(){ ylw "  [~] $*"; }

# ---------------------------------------------------------------- local repo
cmd_scan_repo(){
  local repo="${1:-$PWD}" pattern out art ob
  [ -d "$repo" ] || die "no such directory: $repo"
  FF="$(mktemp -t snarescan)"; trap 'rm -f "$FF"' RETURN
  pattern="$(ioc_pattern)"
  ( cd "$repo" || exit 1
    echo "Scanning: $(pwd)"

    # snare's own source legitimately contains every IOC string. Skip its
    # files rather than reporting the detector as the thing detected.
    local SELF=0 EXCL=()
    if [ -f .snare-tool ]; then
      SELF=1
      EXCL=(--exclude-dir=lib --exclude-dir=bin --exclude=iocs.txt --exclude=README.md --exclude=CHANGELOG.md)
      dim "  (snare's own source tree — its detection patterns are excluded)"
    fi

    hdr "1. Working tree"
    out="$(grep -rInE "$pattern" . --exclude-dir=.git "${EXCL[@]}" 2>/dev/null | head -40)"
    if [ -n "$out" ]; then while IFS= read -r l; do _hit "$(echo "$l" | cut -c1-160)"; done <<< "$out"
    else grn "  clean"; fi

    hdr "2. Auto-execution vectors (run without you typing anything)"
    while IFS= read -r pj; do
      [ -z "$pj" ] && continue
      local h; h="$(python3 -c '
import json,re,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
s=d.get("scripts") or {}
BAD=re.compile(r"node\s+.*(-e|--eval)|curl|wget|base64|\beval\b|child_process|\|\s*(sh|bash)|https?://\d+\.\d+\.\d+\.\d+|atob\(",re.I)
for k in ("preinstall","install","postinstall","prepare","prepublish"):
    v=s.get(k)
    if v: print(("HIGH" if BAD.search(str(v)) else "INFO"), "%s: %s"%(k,v))
' "$pj" 2>/dev/null)"
      [ -z "$h" ] && continue
      echo "$h" | grep -q '^HIGH' && { _hit "$pj suspicious install hook:"; echo "$h" | grep '^HIGH' | sed 's/^HIGH/      /'; }
      echo "$h" | grep -q '^INFO' && dim "      $pj: $(echo "$h" | grep '^INFO' | sed 's/^INFO //' | tr '\n' ';')"
    done < <(find . -name package.json -not -path "*/node_modules/*" 2>/dev/null | head -40)

    while IFS= read -r t; do
      [ -z "$t" ] && continue
      grep -q folderOpen "$t" 2>/dev/null && {
        _hit "$t uses runOn:folderOpen — executes on opening the repo in VS Code"
        grep -n -B2 -A2 folderOpen "$t" | sed 's/^/        /' | head -12; }
    done < <(find . -path "*/.vscode/tasks.json" -not -path "*/node_modules/*" 2>/dev/null)

    while IFS= read -r d; do
      [ -z "$d" ] && continue
      grep -qE "postCreateCommand|postStartCommand|onCreateCommand|initializeCommand" "$d" 2>/dev/null \
        && _hit "$d defines a devcontainer lifecycle command"
    done < <(find . -name devcontainer.json -not -path "*/node_modules/*" 2>/dev/null)

    [ -d .husky ] && { _hit ".husky/ present (runs on git operations)"; ls -1 .husky | sed 's/^/        /'; }
    for hook in .git/hooks/*; do
      [ -f "$hook" ] || continue; case "$hook" in *.sample) continue;; esac
      [ -x "$hook" ] && _hit "active local git hook: $hook"
    done
    [ -f .npmrc ] && { _note "repo-local .npmrc (can redirect the registry):"; sed 's/^/        /' .npmrc; }

    hdr "3. Fake assets (payload disguised as a binary file)"
    local bad=0
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      case "$(head -c 4 "$f" 2>/dev/null)" in
        wOF2|wOFF|$'\x00\x01\x00\x00'|OTTO|"true") ;;               # genuine font magic
        *) _hit "$f is not a real font (no wOF2/OTTO magic) — likely a payload"; bad=1 ;;
      esac
    done < <(find . \( -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' -o -name '*.otf' \) \
             -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -30)
    [ "$bad" = 0 ] && grn "  all font files have valid magic bytes"

    art="$(find . \( -name setup_bun.js -o -name bun_environment.js -o -name 'shai-hulud*' -o -name truffleSecrets\* \) \
         -not -path "*/node_modules/*" 2>/dev/null | head -10)"
    [ -n "$art" ] && while IFS= read -r f; do _hit "known worm artifact: $f"; done <<< "$art"

    hdr "4. Hidden-payload heuristic (very long lines)"
    local lng
    lng="$(find . \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' \) \
        -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -400 \
        | { [ "$SELF" = 1 ] && grep -v '/lib/\|/bin/' || cat; } \
        | xargs awk 'length > 1500 {print FILENAME" line "FNR" ("length" chars)"; nextfile}' 2>/dev/null | head -10)"
    if [ -n "$lng" ]; then while IFS= read -r l; do _hit "$l — payload may be hidden past a run of whitespace"; done <<< "$lng"
    else grn "  no suspiciously long lines"; fi

    if [ "$SELF" = 1 ]; then
      hdr "5. Git history"
      dim "  skipped (snare's own repo)"
    elif git rev-parse --git-dir >/dev/null 2>&1; then
      hdr "5. Git history (all branches, all commits)"
      while IFS= read -r pat; do
        [ -z "$pat" ] && continue
        local c; c="$(git log --all --oneline -S"$pat" --pickaxe-regex 2>/dev/null | head -3)"
        [ -n "$c" ] && { _hit "'$pat' appears in history:"; echo "$c" | sed 's/^/        /'; }
      done < <(ioc_list)
    fi

    local n; n="$(wc -l < "$FF" | tr -d ' ')"
    hdr "RESULT"
    if [ "${n:-0}" -eq 0 ]; then grn "No IOC matches."; exit 0
    else red "$n finding(s). Do NOT run 'npm install' or open this repo in an editor until cleaned."; exit 1; fi
  )
}

# ------------------------------------------------------------------- GitHub
cmd_scan_github(){
  require_gh
  local limit=1000 owner="" allbr=0 scope="accessible"
  while [ $# -gt 0 ]; do
    case "$1" in
      --limit) limit="${2:-1000}"; shift ;;
      --owner) owner="${2:-}"; scope="owner"; shift ;;
      --mine)  scope="mine" ;;
      --all-branches) allbr=1 ;;
    esac; shift
  done
  local flagged="$SNARE_LOGS/flagged.txt"; : > "$flagged"
  local report="$SNARE_LOGS/scan-$(date '+%Y%m%dT%H%M%S').txt"
  local pattern; pattern="$(ioc_pattern)"
  local repos
  case "$scope" in
    owner) repos="$(gh repo list "$owner" --limit "$limit" --json nameWithOwner --jq '.[].nameWithOwner')" ;;
    mine)  repos="$(gh repo list --limit "$limit" --json nameWithOwner --jq '.[].nameWithOwner')" ;;
    *)     repos="$(gh api --paginate "user/repos?affiliation=owner,collaborator,organization_member&per_page=100" --jq '.[].full_name' 2>/dev/null | sort -u)" ;;
  esac
  local total; total="$(echo "$repos" | grep -c . || true)"
  echo "Scanning $total repositories via the API (no cloning)..."
  echo "scan $(date) — $total repos" >> "$report"

  local i=0 R DEF found
  for R in $repos; do
    i=$((i+1)); printf '  [%3d/%3d] %-52s ' "$i" "$total" "$R"
    DEF="$(gh api "repos/$R" --jq '.default_branch' 2>/dev/null)"
    [ -z "$DEF" ] && { echo "skip"; continue; }
    found="$(_scan_ref "$R" "$DEF" "$pattern")"
    if [ "$allbr" = 1 ]; then
      local br
      while IFS= read -r br; do
        [ -z "$br" ] || [ "$br" = "$DEF" ] && continue
        found="${found}$(_scan_ref "$R" "$br" "$pattern")"
      done < <(gh api "repos/$R/branches" --jq '.[].name' 2>/dev/null | head -15)
    fi
    if [ -n "$found" ]; then
      red "INFECTED"; echo "$R" >> "$flagged"
      { echo "[!] $R"; echo "$found"; } >> "$report"
      echo "$found" | sed 's/^/      /'
    else grn "ok"; fi
  done
  echo
  local n; n="$(wc -l < "$flagged" | tr -d ' ')"; n="${n:-0}"
  if [ "$n" -eq 0 ]; then
    grn "No repository tripped a branch-tip check."
    dim "History-only infections are invisible here — run: snare scan repo <clone>"
  else
    red "$n infected repo(s):"; sed 's/^/  - /' "$flagged"
    echo; echo "Next:  snare fix <owner/repo>       (dry run)"
    echo "       snare notify <owner/repo>    (tell collaborators)"
  fi
  echo "report: $report"
}

_scan_ref(){ # $1=repo $2=ref $3=pattern -> prints findings
  local R="$1" REF="$2" pattern="$3" hits="" tree body f
  tree="$(gh api "repos/$R/git/trees/$REF?recursive=1" --jq '.tree[].path' 2>/dev/null)"
  [ -z "$tree" ] && return 0

  echo "$tree" | grep -qE '(^|/)(setup_bun\.js|bun_environment\.js|shai-hulud[^/]*)$' \
    && hits="${hits}    worm artifact filename @$REF
"
  if echo "$tree" | grep -q '^\.vscode/tasks\.json$'; then
    body="$(gh api "repos/$R/contents/.vscode/tasks.json?ref=$REF" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)"
    echo "$body" | grep -q folderOpen && hits="${hits}    .vscode/tasks.json runOn:folderOpen @$REF
"
  fi
  # fake font: fetch only small font files and check magic bytes
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    local head4; head4="$(gh api "repos/$R/contents/$f?ref=$REF" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null | head -c 4)"
    case "$head4" in wOF2|wOFF|OTTO|"true"|"") ;; *) hits="${hits}    $f is not a real font (magic='$head4') @$REF
";; esac
  done < <(echo "$tree" | grep -E '\.(woff2|woff)$' | head -3)

  while IFS= read -r f; do
    [ -z "$f" ] && continue
    body="$(gh api "repos/$R/contents/$f?ref=$REF" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)"
    [ -z "$body" ] && continue
    local hooks; hooks="$(echo "$body" | python3 -c '
import json,re,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
s=d.get("scripts") or {}
BAD=re.compile(r"node\s+.*(-e|--eval)|curl|wget|base64|\beval\b|child_process|\|\s*(sh|bash)|https?://\d+\.\d+\.\d+\.\d+|atob\(",re.I)
for k in ("preinstall","install","postinstall","prepare"):
    v=s.get(k)
    if v and BAD.search(str(v)): print("      %s: %s"%(k,v))
' 2>/dev/null)"
    [ -n "$hooks" ] && hits="${hits}    $f suspicious install hook @$REF:
$hooks
"
    echo "$body" | grep -qE "$pattern" && hits="${hits}    $f matches IOC @$REF
"
  done < <(echo "$tree" | grep -E '(^|/)package\.json$' | grep -v node_modules | head -3)
  printf '%s' "$hits"
}
