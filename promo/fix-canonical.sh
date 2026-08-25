#!/usr/bin/env bash
# fix-canonical.sh — point the dev.to article's canonical URL at the field guide.
# Needs an API key: https://dev.to/settings/extensions ("DEV Community API Keys")
#   printf '%s' 'YOUR_KEY' > ~/.devto_key && chmod 600 ~/.devto_key
set -euo pipefail
ID="${1:-4482155}"
CANON="https://avioflagos.github.io/snare/"

KEY="${DEVTO_API_KEY:-}"
[ -z "$KEY" ] && [ -f "$HOME/.devto_key" ] && KEY="$(tr -d '[:space:]' < "$HOME/.devto_key")"
[ -z "$KEY" ] && { echo "no API key — see the header of this script"; exit 2; }

echo "before: $(curl -s "https://dev.to/api/articles/$ID" -H "api-key: $KEY" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("canonical_url"))')"

RESP="$(curl -sS -X PUT "https://dev.to/api/articles/$ID" \
  -H "api-key: $KEY" -H "Content-Type: application/json" \
  --data "$(python3 -c 'import json,sys;print(json.dumps({"article":{"canonical_url":sys.argv[1]}}))' "$CANON")" \
  -w $'\n%{http_code}')"
CODE="$(printf '%s' "$RESP" | tail -1)"

if [ "$CODE" = "200" ]; then
  echo "after:  $(printf '%s' "$RESP" | sed '$d' | python3 -c 'import json,sys;print(json.load(sys.stdin).get("canonical_url"))')"
  echo "done"
else
  echo "HTTP $CODE"; printf '%s' "$RESP" | sed '$d' | head -c 400; exit 1
fi
