# shellcheck shell=bash
# rotate.sh — what to revoke, in what order, and the GitHub-side audit. Closes #22.
#
# Stealing credentials is this family's objective, not a side effect. Removing
# the dropper does not un-steal a token: anything the loader could read while
# it ran must be treated as compromised, and a stolen npm token with write
# access is how a single infection becomes a supply-chain event.

cmd_rotate(){
  local audit=1
  [ "${1:-}" = "--no-audit" ] && audit=0

  hdr "Rotate these — assume anything readable was read"
  cat <<'LIST'
  Order matters: publish-capable tokens first, because those are what turn one
  infected laptop into a supply-chain incident.

  1. npm tokens                       https://www.npmjs.com/settings/~/tokens
       Revoke write / "bypass 2FA" tokens FIRST — they allow silent publishing
       of new package versions under your name.
       Then: npm token list   /   npm token revoke <id>

  2. GitHub PATs + OAuth apps         https://github.com/settings/tokens
                                      https://github.com/settings/applications
       Classic and fine-grained. Also review authorised OAuth apps and any
       SSH keys:                      https://github.com/settings/keys

  3. Cloud keys
       AWS      aws iam list-access-keys / delete-access-key  (also check
                Secrets Manager in every region you use)
       GCP      gcloud auth revoke  +  rotate service-account keys
       Azure    az ad sp credential reset

  4. Everything else the process could read
       .env files in any project you opened          SSH keys (~/.ssh)
       Kubernetes kubeconfig                          Vault tokens
       Database URLs and passwords                    VPN credentials
       AI service keys (OpenAI, Anthropic, ...)       Crypto wallet keys/seeds

  5. Your clipboard
       This family has a documented clipboard stealer. Anything you copied
       while infected — including a password out of a password manager —
       should be treated as seen.
LIST

  [ "$audit" = 0 ] && return 0
  command -v gh >/dev/null 2>&1 || { echo; ylw "  (install gh for the GitHub-side audit)"; return 0; }
  gh auth status >/dev/null 2>&1 || { echo; ylw "  (run 'gh auth login' for the GitHub-side audit)"; return 0; }

  local me; me="$(gh_user)"
  hdr "GitHub audit for $me"

  # 1. Token scopes still live right now.
  echo "  current token scopes:"
  gh api -i user 2>/dev/null | awk -F': ' '/^[Xx]-[Oo]auth-[Ss]copes:/{print "      "$2}' | tr -d '\r'

  # 2. The worm publishes stolen data to repos it creates on the victim account.
  echo "  repositories matching known exfil names:"
  local bad
  bad="$(gh api "users/$me/repos?per_page=100" --paginate --jq '.[].name' 2>/dev/null \
        | grep -iE 'shai.?hulud|migration|truffle' | head -10)"
  if [ -n "$bad" ]; then
    echo "$bad" | while IFS= read -r r; do red "      [!] $r — review, the worm creates repos to publish stolen data"; done
  else
    grn "      none"
  fi

  # 3. Workflow persistence: exfiltrates secrets on every push, long after the
  #    dropper itself is gone.
  echo "  suspicious Actions workflows across your repos:"
  local found=0 r
  while IFS= read -r r; do
    [ -z "$r" ] && continue
    local wf
    wf="$(gh api "repos/$r/contents/.github/workflows" --jq '.[].name' 2>/dev/null)"
    [ -z "$wf" ] && continue
    local w
    while IFS= read -r w; do
      [ -z "$w" ] && continue
      case "$w" in *shai*|*hulud*) red "      [!] $r/.github/workflows/$w — name matches a known worm artefact"; found=1; continue ;; esac
      local body
      body="$(gh api "repos/$r/contents/.github/workflows/$w" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)"
      [ -z "$body" ] && continue
      # Whole-secret-context dumps, or secrets leaving the runner.
      if echo "$body" | grep -qE 'toJSON\([[:space:]]*secrets|webhook\.site|\$\{\{[[:space:]]*secrets\.[A-Za-z_]+[[:space:]]*\}\}[^\n]*(curl|wget|nc )'; then
        red "      [!] $r/.github/workflows/$w — exports secrets off the runner"
        found=1
      fi
    done <<< "$wf"
  done < <(gh api "user/repos?affiliation=owner&per_page=100" --paginate --jq '.[].full_name' 2>/dev/null | head -60)
  [ "$found" = 0 ] && grn "      none in the repos checked"

  echo
  dim "  A stolen token stays valid until you revoke it. Removing the payload"
  dim "  does not undo the theft."
}
