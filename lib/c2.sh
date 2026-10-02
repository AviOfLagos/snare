# shellcheck shell=bash
# ---------------------------------------------------------------- dead-drop C2
# The 2026-10 loader does not hardcode its C2. It reads the latest transaction
# from a fixed Ethereum sender and takes the first 8 bytes of that
# transaction's `to` address as two IPv4 addresses. The operator rotates the
# C2 by signing a new transaction, so a shipped IP list goes stale by design.
#
# snare reads the same dead drop, so the guard's kill list follows the
# rotation. All of this is read-only: a GET against a public block explorer.
#
# Cost discipline: the guard loop (1s) only ever reads a cached file. The
# refresh is detached, at most once a day, and never blocks a scan.

SNARE_C2_SENDER="${SNARE_C2_SENDER:-0xa322e5f3d311d3080e6f0121063e9adc2490ef1a}"
SNARE_C2_INDEXER="${SNARE_C2_INDEXER:-https://eth.blockscout.com/api}"
C2_CACHE="${SNARE_C2_CACHE:-$SNARE_HOME/c2-cache}"

# Statically known C2s. Kept even when the dead drop is unreachable.
SNARE_C2_BUILTIN="23.27.13.135 193.247.144.38 194.11.226.41 91.218.183.174"

# Every C2 the guard should kill on: builtin + whatever the dead drop resolved.
snare_c2_ips(){
  printf '%s' "$SNARE_C2_BUILTIN"
  if [ -f "$C2_CACHE" ]; then
    printf ' %s' "$(grep -m1 '^ips=' "$C2_CACHE" 2>/dev/null | cut -d= -f2)"
  fi
}

# Decode the first 8 bytes of a 20-byte address into two dotted quads.
# Pure bash: no python in the hot path.
snare_c2_decode(){
  local h="${1#0x}" i o=""
  [ ${#h} -lt 16 ] && return 1
  for i in 0 2 4 6 8 10 12 14; do
    o="$o.$((16#${h:$i:2}))"
    case $i in 6) o="$o " ;; esac
  done
  # o is now ".a.b.c.d .e.f.g.h"; strip the leading dots of each quad.
  printf '%s %s\n' "$(echo "$o" | cut -d' ' -f1 | sed 's/^\.//')" \
                   "$(echo "$o" | cut -d' ' -f2 | sed 's/^\.//')"
}

# Ask the indexer for the sender's most recent transaction and cache the
# decoded C2. Quiet and non-fatal: a failure must never break a scan.
snare_c2_refresh(){
  local url to ips
  url="$SNARE_C2_INDEXER?module=account&action=txlist&address=$SNARE_C2_SENDER"
  url="$url&startblock=0&endblock=99999999&page=1&offset=1&sort=desc&filterby=from"
  to="$(curl -fsS --max-time 20 "$url" 2>/dev/null \
        | snare_py -c 'import json,sys
try:
    r=json.load(sys.stdin).get("result") or []
    print((r[0].get("to") or "") if isinstance(r,list) and r else "")
except Exception:
    print("")' 2>/dev/null)"
  [ -z "$to" ] && return 1
  ips="$(snare_c2_decode "$to")" || return 1
  printf 'checked=%s\nto=%s\nips=%s\n' "$(date +%s)" "$to" "$ips" > "$C2_CACHE.tmp" 2>/dev/null \
    && mv "$C2_CACHE.tmp" "$C2_CACHE" 2>/dev/null
  return 0
}

# Refresh at most once a day, detached, so nothing ever waits on the network.
snare_c2_maybe_refresh(){
  local now checked age
  now="$(date +%s)"; checked=0
  [ -f "$C2_CACHE" ] && checked="$(grep -m1 '^checked=' "$C2_CACHE" 2>/dev/null | cut -d= -f2)"
  [ -z "$checked" ] && checked=0
  age=$(( now - checked ))
  [ "$age" -lt 86400 ] && return 0
  ( "$SNARE_ROOT/bin/snare" _c2-refresh >/dev/null 2>&1 & ) >/dev/null 2>&1
  return 0
}

cmd_c2(){
  case "${1:-status}" in
    --refresh|refresh)
      printf '  resolving dead drop for %s ...\n' "$SNARE_C2_SENDER"
      if snare_c2_refresh; then grn "  ok"; else red "  could not reach the indexer"; return 1; fi ;;
  esac
  hdr "dead-drop C2"
  echo "  sender:  $SNARE_C2_SENDER"
  echo "  builtin: $SNARE_C2_BUILTIN"
  if [ -f "$C2_CACHE" ]; then
    local checked to ips
    checked="$(grep -m1 '^checked=' "$C2_CACHE" | cut -d= -f2)"
    to="$(grep -m1 '^to=' "$C2_CACHE" | cut -d= -f2)"
    ips="$(grep -m1 '^ips=' "$C2_CACHE" | cut -d= -f2)"
    echo "  tx to:   $to"
    grn "  live:    $ips"
    dim "  checked: $(date -r "$checked" '+%F %T' 2>/dev/null || echo "$checked")"
  else
    dim "  no dead-drop lookup cached yet — run: snare c2 --refresh"
  fi
  echo
  dim "  the guard kills any process holding a socket to one of these"
}
