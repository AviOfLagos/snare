# shellcheck shell=bash
# scan.sh — repo scanning: one local repo, or every repo you can reach.

FF=""
_hit(){ echo x >> "$FF"; red "  [!] $*"; }
_note(){ ylw "  [~] $*"; }

# ---------------------------------------------------------------- local repo
cmd_scan_repo(){
  local repo="${1:-$PWD}" pattern out art
  [ -d "$repo" ] || die "no such directory: $repo"
  # GNU mktemp requires the XXXXXX template; BSD/macOS does not. Without it
  # this returns empty on Linux and every later write silently fails.
  FF="$(mktemp "${TMPDIR:-/tmp}/snarescan.XXXXXX")" || die "cannot create a temp file"
  trap 'rm -f "$FF"' RETURN
  pattern="$(ioc_pattern)"
  ( cd "$repo" || exit 1
    echo "Scanning: $(pwd)"

    # snare's own source legitimately contains every IOC string. Skip its
    # files rather than reporting the detector as the thing detected.
    local SELF=0 EXCL=()
    if [ -f .snare-tool ]; then
      SELF=1
      # promo/ and docs/ quote every IOC verbatim; they are write-ups about the
      # malware, not the malware. Without them snare cannot pass its own CI.
      # The plugin manifest and the skill describe the malware, so they quote
      # its keywords the same way promo/ and docs/ do. Excluded only when the
      # .snare-tool marker is present, i.e. only in snare's own checkout.
      EXCL=(--exclude-dir=lib --exclude-dir=bin --exclude-dir=docs --exclude-dir=promo
            --exclude-dir=.github --exclude-dir=.claude-plugin --exclude-dir=skills
            --exclude=iocs.txt --exclude=README.md --exclude=CHANGELOG.md)
      dim "  (snare's own source tree — its detection patterns are excluded)"
    fi

    hdr "1. Working tree"
    out="$(grep -rInE "$pattern" . --exclude-dir=.git ${EXCL[@]+"${EXCL[@]}"} 2>/dev/null | head -40)"
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

    # Actions workflow persistence. This family's documented persistence is a
    # workflow that exfiltrates secrets on EVERY push, and it survives long
    # after the dropper is removed. Filename matching is not enough — the file
    # need not be called anything distinctive, so check content.
    local wf
    while IFS= read -r wf; do
      [ -z "$wf" ] && continue
      case "$wf" in *shai*|*hulud*) _hit "$wf — workflow filename matches a known worm artefact"; continue ;; esac
      if grep -qE 'toJSON\([[:space:]]*secrets' "$wf" 2>/dev/null; then
        _hit "$wf — dumps the entire secrets context (toJSON(secrets))"
      elif grep -qE 'webhook\.site|pipedream\.net|requestbin' "$wf" 2>/dev/null; then
        _hit "$wf — posts to a known exfiltration endpoint"
      elif grep -qE '\$\{\{[[:space:]]*secrets\.' "$wf" 2>/dev/null \
           && grep -qE 'curl|wget|nc |Invoke-WebRequest' "$wf" 2>/dev/null; then
        _note "$wf — references secrets near an outbound request; read it"
      fi
    done < <(find . -path '*/.github/workflows/*' \( -name '*.yml' -o -name '*.yaml' \) \
             -not -path '*/node_modules/*' 2>/dev/null | head -30)

    hdr "3. Fake assets (payload disguised as a binary file)"
    local bad=0
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      # Compare as hex: bash cannot hold NUL, so the TrueType magic
      # 00 01 00 00 can never match as a literal string.
      if ! is_font "$f"; then
        _hit "$f is not a real font (no wOF2/OTTO magic) — likely a payload"; bad=1
      fi
    done < <(find . \( -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' -o -name '*.otf' \) \
             -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -30)
    [ "$bad" = 0 ] && grn "  all font files have valid magic bytes"

    art="$(find . \( -name setup_bun.js -o -name bun_environment.js -o -name 'shai-hulud*' -o -name truffleSecrets\* \) \
         -not -path "*/node_modules/*" 2>/dev/null | head -10)"
    [ -n "$art" ] && while IFS= read -r f; do _hit "known worm artifact: $f"; done <<< "$art"

    hdr "4. Hidden-payload heuristic (code hidden past whitespace)"
    local files hid lng
    # Two signals: the structural one (code, a long whitespace run, then more
    # code) catches a payload of ANY length; the raw-length one catches a
    # minified blob that hides without a whitespace run. Length alone missed
    # real samples, so the structural test is primary.
    #
    # The structural test runs through grep, not awk. mawk — the default awk on
    # Debian and Ubuntu — accepts but silently ignores {50,} interval
    # expressions, so the awk form matched nothing and the primary test was a
    # no-op on those hosts. grep -E is the engine _scan_ref, fix and hook
    # already use for this exact pattern.
    files="$(find . \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' \) \
        -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -400 \
        | { [ "$SELF" = 1 ] && grep -v '/lib/\|/bin/\|/docs/\|/promo/' || cat; } )"
    hid="$(printf '%s\n' "$files" | xargs grep -lE '[^[:space:]][[:space:]]{50,}[^[:space:]]' 2>/dev/null | head -20)"
    lng="$(printf '%s\n' "$files" | xargs awk 'length > 1500 {print "LONG "FILENAME" line "FNR" ("length" chars)"; nextfile}' 2>/dev/null | head -20)"
    local anyhit=0
    if [ -n "$hid" ]; then
      while IFS= read -r f; do
        [ -n "$f" ] || continue
        _hit "$f — code hidden past a run of whitespace"; anyhit=1
      done <<< "$hid"
    fi
    if [ -n "$lng" ]; then
      while IFS= read -r l; do
        # A long line on its own is weak evidence: minified bundles are
        # legitimately long. Report it, but do not count it as a finding.
        _note "${l#LONG } — very long line (minified code looks like this too)"
      done <<< "$lng"
    fi
    [ "$anyhit" = 0 ] && grn "  no code hidden past whitespace"

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

    local n
  n="$(wc -l < "$FF" | tr -d ' ')"
    hdr "RESULT"
    if [ "${n:-0}" -eq 0 ]; then grn "No IOC matches."; exit 0
    else red "$n finding(s). Do NOT run 'npm install' or open this repo in an editor until cleaned."; exit 1; fi
  )
}

# ------------------------------------------------------------ owner listing
# Which accounts and organisations can this token actually reach? Without this
# the only way to narrow a scan was to already know an org's exact login, and
# the only alternative was scanning every repository you can see — which on a
# real account is hundreds of repositories and thousands of API calls.

# The set of owners, cheaply: login \t type.
_scan_owners_set(){
  { # Owners of the repositories you are attached to. No extra scope needed.
    gh api --paginate \
      'user/repos?affiliation=owner,collaborator,organization_member&per_page=100' \
      --jq '.[] | [.owner.login, .owner.type] | @tsv' 2>/dev/null
    # Organisations you belong to but hold no repository in directly. Needs
    # read:org; without it this adds nothing and the listing is merely shorter.
    gh api user/orgs --jq '.[].login' 2>/dev/null | while IFS= read -r o; do
      [ -n "$o" ] && printf '%s\tOrganization\n' "$o"
    done
  } | awk -F'\t' '$1 != "" && !seen[$1]++ { print $1 "\t" $2 }' | sort -f
}

# Count each owner with the SAME call the scan uses, because a listing whose
# numbers disagree with the scan is worse than no listing. The affiliation
# endpoint under-reports: it returns only repositories you are directly
# attached to, while scanning an owner covers everything you can see there.
_scan_count_one(){ # $1=login $2=type
  local json total priv
  json="$(gh repo list "$1" --limit "${SNARE_OWNER_LIMIT:-1000}" \
          --json isPrivate --jq '.[].isPrivate' 2>/dev/null)"
  total="$(printf '%s' "$json" | grep -c . || true)"
  priv="$(printf '%s' "$json" | grep -c true || true)"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "${total:-0}" "${priv:-0}"
}

_scan_owner_counts(){ # $1=file of login\ttype -> login\ttype\ttotal\tprivate
  local login type i=0 n d par
  n="$(grep -c . "$1" 2>/dev/null | tr -d ' ')"
  d="$(mktemp -d "${TMPDIR:-/tmp}/snarecount.XXXXXX")" || return 1
  # One call per owner, in bounded batches. Sequentially this took 41 seconds
  # on an account with 22 organisations, which is long enough that people stop
  # using the command. Bounded, because dozens of concurrent calls get you
  # rate-limited rather than answered.
  par="${SNARE_COUNT_JOBS:-8}"
  while IFS="$(printf '\t')" read -r login type; do
    [ -z "$login" ] && continue
    i=$((i+1))
    _scan_count_one "$login" "$type" > "$d/$(printf '%04d' "$i")" &
    if [ $((i % par)) -eq 0 ]; then
      wait
      # Only animate for a human: piped into a file or a pager, a \r progress
      # line just concatenates into one unreadable smear.
      [ -t 2 ] && printf '\r  counting %s/%s...' "$i" "${n:-?}" >&2
    fi
  done < "$1"
  wait
  [ -t 2 ] && printf '\r%*s\r' 40 '' >&2
  # Zero-padded names, so the glob restores the input order.
  cat "$d"/* 2>/dev/null
  rm -rf "$d"
}

# Everything the table needs, filtered and sorted biggest-first.
_scan_owners_load(){ # $1=all(0|1)  $2=me  $3=path to write the full set to
  local keep
  keep="$(mktemp "${TMPDIR:-/tmp}/snareowners.XXXXXX")" || return 1
  _scan_owners_set > "$3"
  # Someone asking which orgs they are in does not want dozens of personal
  # accounts they hold a single collaborator bit on.
  awk -F'\t' -v me="$2" -v all="$1" \
    '$1 == me || $2 == "Organization" || all == "1"' "$3" > "$keep"
  _scan_owner_counts "$keep" | sort -t"$(printf '\t')" -k3,3nr -k1,1f
  rm -f "$keep"
}

_scan_owner_table(){ # $1=file of login\ttype\ttotal\tprivate  $2=me
  local i=0 login type total priv label
  printf '  %3s  %-28s %-5s %7s %9s\n' "#" "OWNER" "TYPE" "REPOS" "PRIVATE"
  while IFS="$(printf '\t')" read -r login type total priv; do
    [ -z "$login" ] && continue
    i=$((i+1))
    if   [ "$login" = "$2" ];          then label="you"
    elif [ "$type" = "Organization" ]; then label="org"
    else                                    label="user"; fi
    printf '  %3d  %-28s %-5s %7s %9s\n' "$i" "$login" "$label" "$total" "$priv"
  done < "$1"
}

cmd_scan_orgs(){
  require_gh
  local all=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --all) all=1 ;;
      *) red "unknown flag: $1"; echo "  usage: snare scan orgs [--all]"; return 2 ;;
    esac; shift
  done

  local full sel me
  full="$(mktemp "${TMPDIR:-/tmp}/snareowners.XXXXXX")" || die "cannot create a temp file"
  sel="$(mktemp  "${TMPDIR:-/tmp}/snareowners.XXXXXX")" || die "cannot create a temp file"
  # shellcheck disable=SC2064
  trap "rm -f '$full' '$sel'" RETURN

  me="$(gh_user)"
  echo "Reading the accounts and organisations you can reach..."
  _scan_owners_load "$all" "$me" "$full" > "$sel"

  local n; n="$(grep -c . "$sel" 2>/dev/null | tr -d ' ')"
  if [ "${n:-0}" -eq 0 ]; then
    ylw "  no owners found — is this token scoped to any repositories?"
    return 0
  fi

  hdr "Owners you can reach"
  _scan_owner_table "$sel" "$me"

  local repos hidden first
  repos="$(awk -F'\t' '{s += $3} END {print s+0}' "$sel")"
  echo
  echo "  $n owner(s), $repos repositor(ies) you could scan through them."
  if [ "$all" = 0 ]; then
    hidden="$(awk -F'\t' -v me="$me" '$1 != me && $2 != "Organization"' "$full" | grep -c . || true)"
    [ "${hidden:-0}" -gt 0 ] && \
      dim "  $hidden individual account(s) not shown — snare scan orgs --all"
  fi
  first="$(head -1 "$sel" | cut -f1)"
  echo
  dim "  scan one:      snare scan github --owner $first"
  dim "  scan several:  snare scan github --owner a,b,c"
  dim "  choose here:   snare scan github --pick"
}

# Render the same table and read a selection. Prompts go to stderr so the
# chosen logins can be captured from stdout.
_scan_pick_owners(){ # $1=all(0|1) -> selected logins on stdout
  local full sel me n input idx
  full="$(mktemp "${TMPDIR:-/tmp}/snarepick.XXXXXX")" || return 1
  sel="$(mktemp  "${TMPDIR:-/tmp}/snarepick.XXXXXX")" || return 1
  # shellcheck disable=SC2064
  trap "rm -f '$full' '$sel'" RETURN

  me="$(gh_user)"
  echo "Reading the accounts and organisations you can reach..." >&2
  _scan_owners_load "$1" "$me" "$full" > "$sel"
  n="$(grep -c . "$sel" 2>/dev/null | tr -d ' ')"
  [ "${n:-0}" -eq 0 ] && { red "  no owners found" >&2; return 1; }

  {
    printf '\n%s== Choose what to scan ==%s\n' "$C_BLD" "$C_OFF"
    _scan_owner_table "$sel" "$me"
    echo
    echo "  Numbers, ranges or 'all'   e.g.  2      2,5      1-4      2,7-9"
    [ "$1" = 0 ] && echo "  Individual accounts are hidden — cancel and add --all to include them"
    printf '  Select (empty cancels): '
  } >&2

  read -r input
  echo >&2
  [ -z "$input" ] && return 0

  idx="$(_scan_parse_sel "$input" "$n")"
  [ -z "$idx" ] && { red "  nothing valid in '$input'" >&2; return 1; }
  printf '%s\n' "$idx" | while IFS= read -r i; do
    [ -z "$i" ] && continue
    sed -n "${i}p" "$sel" | cut -f1
  done
}

# "2,7-9" / "all" -> one index per line, sorted, deduplicated, in range.
_scan_parse_sel(){ # $1=input  $2=max
  local max="$2"
  # The trailing newline matters: without it `read` drops the final token, so
  # "2,5" selected only 2 and "all" selected nothing at all.
  printf '%s\n' "$1" | tr ',' ' ' | tr -s '[:space:]' '\n' | while IFS= read -r tok; do
    [ -z "$tok" ] && continue
    case "$tok" in
      all|ALL|a|A) seq 1 "$max" ;;
      *-*)
        lo="${tok%%-*}"; hi="${tok##*-}"
        case "$lo$hi" in ""|*[!0-9]*) continue ;; esac
        [ "$lo" -ge 1 ] && [ "$hi" -le "$max" ] && [ "$lo" -le "$hi" ] && seq "$lo" "$hi" ;;
      *)
        case "$tok" in *[!0-9]*) continue ;; esac
        [ "$tok" -ge 1 ] && [ "$tok" -le "$max" ] && echo "$tok" ;;
    esac
  done | sort -un
}

# ------------------------------------------------------------------- GitHub
cmd_scan_github(){
  require_gh
  local limit=1000 owner="" allbr=0 scope="accessible" pick=0 all=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --limit) limit="${2:-1000}"; shift ;;
      --owner) owner="${2:-}"; scope="owner"; shift ;;
      --mine)  scope="mine" ;;
      --pick|--select) pick=1; scope="owner" ;;
      --all)   all=1 ;;
      --all-branches) allbr=1 ;;
      # An unknown flag used to be ignored in silence, so a typo like
      # --all-branch quietly scanned every repository you can reach instead of
      # the one thing you asked for.
      *) red "unknown flag: $1"; echo "  see: snare help"; return 2 ;;
    esac; shift
  done

  if [ "$pick" = 1 ]; then
    if [ ! -t 0 ] || [ ! -t 1 ] || [ -n "${CI:-}" ]; then
      red "--pick needs a terminal."
      echo "  list what is reachable:  snare scan orgs"
      echo "  then scan by name:       snare scan github --owner acme,other"
      return 2
    fi
    owner="$(_scan_pick_owners "$all")" || return 2
    [ -z "$owner" ] && { ylw "nothing selected — nothing scanned"; return 0; }
  fi
  local flagged="$SNARE_LOGS/flagged.txt"; : > "$flagged"
  local report
  report="$SNARE_LOGS/scan-$(date '+%Y%m%dT%H%M%S').txt"
  local pattern; pattern="$(ioc_pattern)"
  local repos
  case "$scope" in
    owner)
      local o acc=""
      for o in $(printf '%s' "$owner" | tr ',' ' '); do
        [ -z "$o" ] && continue
        acc="$acc
$(gh repo list "$o" --limit "$limit" --json nameWithOwner --jq '.[].nameWithOwner' 2>/dev/null)"
      done
      repos="$(printf '%s\n' "$acc" | grep . | sort -u)" ;;
    mine)  repos="$(gh repo list --limit "$limit" --json nameWithOwner --jq '.[].nameWithOwner')" ;;
    *)     repos="$(gh api --paginate "user/repos?affiliation=owner,collaborator,organization_member&per_page=100" --jq '.[].full_name' 2>/dev/null | sort -u)" ;;
  esac
  local total; total="$(echo "$repos" | grep -c . || true)"
  [ "$scope" = owner ] && \
    echo "Owners: $(printf '%s' "$owner" | tr ',\n' '  ' | tr -s ' ')"
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
    echo
    # Order matters and the old order was wrong. It led with "fix", which is
    # the LAST thing to do: credentials are this family's objective, and a
    # still-infected machine re-injects into whatever you just cleaned.
    red "  Do these in order — cleaning the repos first is wasted work."
    echo
    echo "  1. Rotate your credentials.  snare rotate"
    dim  "     Stealing them is the point; removing the payload does not"
    dim  "     un-steal a token. npm write tokens first."
    echo "  2. Check THIS machine.       snare doctor    and    snare guard scan"
    if [ "$n" -ge 3 ]; then
      dim  "     $n infected repositories points at the machine that pushed to"
      dim  "     them, not at $n separate accidents. Clean it before step 3, or"
      dim  "     it will re-inject into everything you just fixed."
    else
      dim  "     This family injects from an already-infected machine."
    fi
    echo "  3. Then clean the repos.     snare fix <owner/repo>       (dry run)"
    echo "                               snare fix --all             (dry run)"
    echo "  4. Then tell collaborators.  snare notify <owner/repo>"
  fi
  # Same reasoning as doctor: this command already waited on the network.
  snare_update_refresh 2>/dev/null || true
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
    local head4; head4="$(gh api "repos/$R/contents/$f?ref=$REF" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null | head -c 4 | od -An -v -tx1 2>/dev/null | tr -d ' \n')"
    case "$head4" in 774f4632|774f4646|00010000|4f54544f|74727565|"") ;; *) hits="${hits}    $f is not a real font (magic=0x$head4) @$REF
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
  # Auto-loaded configs: the documented execution routes. next dev / next build
  # require()s the postcss/next configs, and ESLint's flat config (eslint.config.*)
  # runs in an editor with the ESLint extension on folder open, and in any lint
  # script. That pattern is the only thing that fetches these files, so omit
  # eslint here and an infection in an eslint config is invisible to the API scan.
  # The payload is obfuscated and matches no IOC string, so it is only visible
  # via the hidden-payload heuristic — a run of whitespace followed by code.
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    body="$(gh api "repos/$R/contents/$f?ref=$REF" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)"
    [ -z "$body" ] && continue
    if echo "$body" | grep -qE '[^[:space:]][[:space:]]{50,}[^[:space:]]'; then
      hits="${hits}    $f hides code past a run of whitespace @$REF
"
    fi
    echo "$body" | grep -qE "$pattern" && hits="${hits}    $f matches IOC @$REF
"
  done < <(echo "$tree" | grep -E '(^|/)(postcss|next|tailwind|vite|svelte|nuxt|astro|rollup|webpack|babel|eslint)\.config\.[cm]?[jt]s$' \
           | grep -v node_modules | head -8)

  printf '%s' "$hits"
}
