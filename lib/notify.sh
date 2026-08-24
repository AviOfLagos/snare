# shellcheck shell=bash
# notify.sh — tell the people who share an infected repo.
#   snare notify <owner/repo>            list contacts + preview (sends nothing)
#   snare notify <owner/repo> --issue    file a GitHub issue @-mentioning them
#   snare notify <owner/repo> --mail     open a pre-filled draft per person
#   snare notify <owner/repo> --issue --mail

_notify_body(){ # $1=repo $2=issue-ref-or-empty
  local repo="$1" ref="${2:-}"
  cat <<MD
## Malware was committed to this repository

**Status: removed.** The payload has been deleted. This notice exists so that
everyone with a local clone checks their own machine — cloning or simply
opening this repo was enough to execute it.

### What was here

Droppers of this family hide in one of two places:

- **\`.vscode/tasks.json\`** — a task with an innocuous label (e.g. \`eslint-check\`),
  marked \`"hide": true\` / \`"reveal": "never"\`, set to \`"runOn": "folderOpen"\`.
  **Opening the folder in VS Code runs it.**
- **A config file loaded by the build** (e.g. \`postcss.config.js\`) — the payload is
  appended after thousands of spaces on one line, so the file looks normal in an
  editor. It runs on \`next dev\` / \`next build\`.

The executed file is often disguised as an asset, e.g. \`public/fonts/*.woff2\`.
A genuine \`.woff2\` begins with the magic bytes \`wOF2\`; these begin with spaces.

**Neither route needs \`npm install\`.**

### What it does

It resolves its command-and-control address *from the Ethereum blockchain*
(transactions from \`0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a\` read via the
Blockscout API), decodes an IPv4 address out of them, downloads a second stage
and \`spawn\`s it detached. Observed second stage: a clipboard stealer capturing
everything copied. Because the C2 lives on-chain the attacker rotates it freely —
**blocking a single IP does not help.**

### Check your machine

\`\`\`bash
# running right now?
ps axww | grep -E "node .*-e .*global\[|osascript.*Pasteboard" | grep -v grep

# your local clones
grep -rn "0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a" .
grep -rn "folderOpen" .vscode/tasks.json 2>/dev/null
head -c 4 public/fonts/*.woff2 2>/dev/null   # a real font prints wOF2
\`\`\`

### Then

1. **Delete your local clone and re-clone.** If history was rewritten, a \`git pull\`
   will conflict — you must re-clone.
2. **Rotate credentials**: GitHub tokens (github.com/settings/tokens), SSH keys,
   npm tokens, \`.env\` values, and anything copied to your clipboard.
3. Check your GitHub account for repos, keys or OAuth apps you did not create.

Scanned and cleaned with [snare](https://github.com/) — \`snare scan repo .\` to check your own clones.
MD
}

cmd_notify(){
  require_gh
  local repo="${1:-}"; shift || true
  [ -n "$repo" ] || die "usage: snare notify <owner/repo> [--issue] [--mail]"
  local do_issue=0 do_mail=0
  while [ $# -gt 0 ]; do
    case "$1" in --issue) do_issue=1 ;; --mail) do_mail=1 ;; --all) do_issue=1; do_mail=1 ;; esac; shift
  done

  hdr "Collaborators on $repo"
  local logins
  logins="$(gh api "repos/$repo/collaborators" --jq '.[].login' 2>/dev/null)"
  [ -z "$logins" ] && ylw "  (cannot list collaborators — needs admin; falling back to commit authors)"
  local me; me="$(gh_user)"

  # Emails: public profile first, then commit metadata. noreply addresses cannot receive mail.
  local contacts="$SNARE_LOGS/contacts-$(echo "$repo" | tr '/' '_').tsv"; : > "$contacts"
  local u e n
  for u in $logins; do
    [ "$u" = "$me" ] && continue
    e="$(gh api "users/$u" --jq '.email // empty' 2>/dev/null)"
    n="$(gh api "users/$u" --jq '.name // empty' 2>/dev/null)"
    printf '%s\t%s\t%s\n' "$u" "${e:-}" "${n:-}" >> "$contacts"
  done
  # commit authors (real addresses only)
  local src="$SNARE_WORK/$(echo "$repo" | tr '/' '_')"
  if [ -d "$src/.git" ]; then
    git -C "$src" log --all --format='%ae%x09%an' 2>/dev/null | sort -u | \
      grep -v 'users\.noreply\.github\.com' | grep -v 'noreply@' | grep -v 'you@example' | \
      while IFS=$'\t' read -r ae an; do printf '(commit)\t%s\t%s\n' "$ae" "$an" >> "$contacts"; done
  fi
  sort -u -o "$contacts" "$contacts"
  column -t -s$'\t' "$contacts" 2>/dev/null | sed 's/^/  /' || cat "$contacts"
  local reachable; reachable="$(awk -F'\t' '$2!=""{print $2}' "$contacts" | sort -u | grep -c . || true)"
  echo; dim "  contacts file: $contacts"
  dim "  reachable by email: ${reachable:-0}   (the rest: reach via the GitHub issue)"

  if [ "$do_issue" = 1 ]; then
    hdr "Filing GitHub issue"
    local mentions body url
    mentions="$(for u in $logins; do [ "$u" = "$me" ] || printf '@%s ' "$u"; done)"
    body="${mentions:+$mentions— flagging this for you.

}$(_notify_body "$repo")"
    url="$(gh issue create --repo "$repo" \
      --title "Security: malware was committed to this repo (removed) — please check your machine" \
      --body "$body" 2>&1 | tail -1)"
    grn "  $url"
  fi

  if [ "$do_mail" = 1 ]; then
    hdr "Opening mail drafts (nothing is sent)"
    local sent=0
    while IFS=$'\t' read -r who email name; do
      [ -z "$email" ] && continue
      python3 - "$email" "$name" "$repo" <<'PY'
import urllib.parse, subprocess, sys
email, name, repo = sys.argv[1], sys.argv[2] or "there", sys.argv[3]
subject = f"Security: malware in {repo} - please check your machine"
body = f"""Hi {name.split()[0] if name.strip() else 'there'} - real security notice, not spam. You can verify all of
this against the repository itself.

Malware was committed into {repo}, which we both have access to. It has been
removed. There is a GitHub issue on the repo with the full write-up.

HOW IT INFECTED PEOPLE (neither step needs npm install):
1. .vscode/tasks.json - a hidden task with runOn:folderOpen. Simply OPENING
   the folder in VS Code executed it.
2. A build config file (e.g. postcss.config.js) with the payload appended
   after thousands of spaces on one line, so the file looks normal. It ran
   on every `next dev` / `next build`.
The executed file was disguised as a font: a real .woff2 starts with wOF2.

It pulls its command-and-control address from the Ethereum blockchain, so
blocking a single IP does not stop it. The second stage was a clipboard
stealer that captured everything copied.

PLEASE CHECK:
  ps axww | grep -E "node .*-e .*global\\[|osascript.*Pasteboard" | grep -v grep
  grep -rn "0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a" .
  head -c 4 public/fonts/*.woff2

THEN:
- Delete old clones and re-clone (a pull may conflict if history was rewritten).
- Rotate GitHub tokens, SSH keys, npm tokens, .env values, and anything you
  copied to your clipboard. Check your account for repos/keys you did not create.

Happy to walk you through it.
"""
url = ("mailto:" + urllib.parse.quote(email) +
       "?subject=" + urllib.parse.quote(subject) +
       "&body=" + urllib.parse.quote(body))
subprocess.run(["open", url])
print(f"  draft -> {email}")
PY
      sent=$((sent+1)); sleep 1
    done < "$contacts"
    [ "$sent" = 0 ] && ylw "  no reachable email addresses — use --issue instead"
    [ "$sent" -gt 0 ] && dim "  $sent draft(s) opened. Review each, then send from your own account."
  fi

  if [ "$do_issue" = 0 ] && [ "$do_mail" = 0 ]; then
    hdr "Preview (nothing sent)"
    _notify_body "$repo" | head -20
    dim "  ..."
    echo; ylw "  snare notify $repo --issue   file the GitHub issue"
    ylw "  snare notify $repo --mail    open a mail draft per person"
  fi
}
