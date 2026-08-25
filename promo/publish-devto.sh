#!/usr/bin/env bash
# publish-devto.sh — post devto-article.md to dev.to via the Forem API.
#
#   ./publish-devto.sh --dry-run     show exactly what would be sent
#   ./publish-devto.sh --draft       create it unpublished
#   ./publish-devto.sh               create it published
#
# Reads the API key from $DEVTO_API_KEY, or ~/.devto_key if that is unset.
# Get one at: https://dev.to/settings/extensions  ->  "DEV Community API Keys"
set -euo pipefail
cd "$(dirname "$0")"

ART="devto-article.md"
DRY=0; PUBLISH=true
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --draft)   PUBLISH=false ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
  esac; shift
done

[ -f "$ART" ] || { echo "missing $ART"; exit 1; }

KEY="${DEVTO_API_KEY:-}"
if [ -z "$KEY" ] && [ -f "$HOME/.devto_key" ]; then KEY="$(tr -d '[:space:]' < "$HOME/.devto_key")"; fi
if [ -z "$KEY" ] && [ "$DRY" = "0" ]; then
  echo "No API key found."
  echo "  Get one at https://dev.to/settings/extensions (\"DEV Community API Keys\")"
  echo "  Then:  printf '%s' 'YOUR_KEY' > ~/.devto_key && chmod 600 ~/.devto_key"
  exit 2
fi

# Split front matter from body and build the request payload.
PAYLOAD="$(python3 - "$ART" "$PUBLISH" <<'PY'
import json,sys,re
path,published = sys.argv[1], sys.argv[2] == "true"
raw = open(path, encoding="utf-8").read()
m = re.match(r'^---\n(.*?)\n---\n(.*)$', raw, re.S)
if not m:
    print(json.dumps({"error":"no front matter"})); sys.exit(1)
fm, body = m.group(1), m.group(2).lstrip("\n")
meta = {}
for line in fm.split("\n"):
    if ":" not in line: continue
    k, v = line.split(":", 1)
    meta[k.strip()] = v.strip().strip('"')
art = {
    "title": meta.get("title",""),
    "body_markdown": body,          # front matter stripped: fields are explicit below
    "published": published,
    "tags": [t.strip() for t in meta.get("tags","").split(",") if t.strip()][:4],
}
if meta.get("canonical_url"): art["canonical_url"] = meta["canonical_url"]
if meta.get("description"):   art["description"]   = meta["description"]
print(json.dumps({"article": art}))
PY
)"

echo "=== request ==="
python3 -c "
import json,sys
d=json.loads(sys.argv[1])['article']
print('  title:      ', d['title'])
print('  tags:       ', ', '.join(d['tags']))
print('  published:  ', d['published'])
print('  canonical:  ', d.get('canonical_url','(none)'))
print('  body:       ', len(d['body_markdown']), 'chars')
print('  front matter stripped:', 'no ---' if not d['body_markdown'].startswith('---') else 'STILL PRESENT')
" "$PAYLOAD"

if [ "$DRY" = "1" ]; then echo; echo "dry run — nothing sent"; exit 0; fi

echo
echo "=== POST https://dev.to/api/articles ==="
RESP="$(curl -sS -X POST "https://dev.to/api/articles" \
  -H "api-key: $KEY" -H "Content-Type: application/json" \
  --data "$PAYLOAD" -w $'\n%{http_code}')"
CODE="$(printf '%s' "$RESP" | tail -1)"
BODY="$(printf '%s' "$RESP" | sed '$d')"

if [ "$CODE" = "201" ]; then
  URL="$(printf '%s' "$BODY" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("url",""))')"
  echo "  published: $URL"
  echo "$URL" > .devto_url
  echo
  echo "Next:  cd ../docs && ./set-links.sh --devto $URL"
else
  echo "  HTTP $CODE"
  printf '%s' "$BODY" | head -c 600
  exit 1
fi
