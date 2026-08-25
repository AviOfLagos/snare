#!/usr/bin/env bash
# set-links.sh — drop the real discussion links into the Reports section.
#
#   ./set-links.sh --tweet https://x.com/you/status/123
#   ./set-links.sh --devto https://dev.to/you/slug
#   ./set-links.sh --tweet URL --devto URL
#
# Rebuilds index.html afterwards. Then: git commit -am "links" && git push
set -euo pipefail
cd "$(dirname "$0")"

TWEET=""; DEVTO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tweet) TWEET="${2:-}"; shift ;;
    --devto) DEVTO="${2:-}"; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac; shift
done
[ -z "$TWEET" ] && [ -z "$DEVTO" ] && { echo "nothing to do — pass --tweet and/or --devto"; exit 2; }

for u in "$TWEET" "$DEVTO"; do
  [ -z "$u" ] && continue
  case "$u" in https://*) ;; *) echo "error: '$u' must start with https://"; exit 1 ;; esac
done

X_ICON='<path d="M12.6 1.5h2.3l-5 5.8 5.9 7.8h-4.6l-3.6-4.7-4.1 4.7H1.2l5.4-6.2L1 1.5h4.7l3.3 4.3 3.6-4.3Zm-.8 12.2h1.3L4.6 2.8H3.2l8.6 10.9Z"/>'
D_ICON='<path d="M2 3h3.1c1.9 0 3.2 1.2 3.2 3v4c0 1.8-1.3 3-3.2 3H2V3Zm2.1 2v6h1c.8 0 1.2-.4 1.2-1.2V6.2C6.3 5.4 5.9 5 5.1 5h-1Zm5.6-2h2l1.1 5.2L14 3h2l-2.2 10h-1.9L9.7 3Z"/>'

swap(){ # $1=marker $2=url $3=icon-path $4=title $5=subtitle
  python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import re,sys
marker,url,icon,title,sub = sys.argv[1:6]
p='_source.html'; s=open(p).read()
block = (f'<!-- LINK:{marker}:start -->\n'
         f'    <a class="report-link" href="{url}">\n'
         f'      <span class="ic"><svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">{icon}</svg></span>\n'
         f'      <span><b>{title}</b><span>{sub}</span></span>\n'
         f'    </a>\n'
         f'<!-- LINK:{marker}:end -->')
pat = re.compile(r'<!-- LINK:%s:start -->.*?<!-- LINK:%s:end -->' % (marker,marker), re.S)
if not pat.search(s):
    print(f"  marker '{marker}' not found — already replaced?"); sys.exit(1)
open(p,'w').write(pat.sub(lambda _: block, s))
print(f"  {marker} -> {url}")
PY
}

[ -n "$TWEET" ] && swap tweet "$TWEET" "$X_ICON" "Discussion on X" "Developers sharing what they saw — add yours."
[ -n "$DEVTO" ] && swap devto "$DEVTO" "$D_ICON" "Write-up on dev.to" "Full technical breakdown, with comments."

./build.sh
echo
echo "Done. Now:"
echo "  git commit -am 'site: add discussion links' && git push"
