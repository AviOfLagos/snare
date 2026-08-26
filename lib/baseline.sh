# shellcheck shell=bash
# baseline.sh — report only what is new. Closes #8.
#
# A scheduled scan that reprints the same findings every run gets ignored,
# and an ignored scanner is the same as no scanner.

SNARE_BASELINES="$SNARE_HOME/baselines"
mkdir -p "$SNARE_BASELINES" 2>/dev/null

# Stable identity for a repo path: prefer the origin URL so the same project
# keeps one baseline across clones in different directories.
_bl_key(){
  local d="${1:-$PWD}" url
  url="$(git -C "$d" config --get remote.origin.url 2>/dev/null)"
  [ -z "$url" ] && url="$(cd "$d" 2>/dev/null && pwd)"
  printf '%s' "$url" | shasum 2>/dev/null | cut -c1-16
}

_bl_file(){ printf '%s/%s.txt' "$SNARE_BASELINES" "$(_bl_key "${1:-$PWD}")"; }

# Fingerprint a finding so cosmetic changes (line numbers shifting, column
# widths) do not make an accepted finding look new. Path + the distinctive
# text, with digits collapsed.
_bl_fingerprint(){
  sed 's/^  *\[!\] *//' \
    | sed 's/:[0-9][0-9]*:/:/g' \
    | tr -s ' ' \
    | sed 's/[0-9]\{3,\}/N/g' \
    | shasum 2>/dev/null | cut -c1-16
}

cmd_baseline(){
  local sub="${1:-status}"; shift || true
  local dir="${1:-$PWD}"
  case "$sub" in
    set)
      git -C "$dir" rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository: $dir"
      local out; out="$(cmd_scan_repo "$dir" 2>&1)"
      local f; f="$(_bl_file "$dir")"
      : > "$f"
      echo "$out" | grep '\[!\]' | while IFS= read -r l; do
        printf '%s  %s\n' "$(printf '%s' "$l" | _bl_fingerprint)" "$(printf '%s' "$l" | cut -c1-120)" >> "$f"
      done
      local n; n="$(grep -c . "$f" 2>/dev/null | tr -d ' ')"
      grn "  baseline set: ${n:-0} finding(s) accepted for $dir"
      dim "  $f"
      ylw "  Accepting a finding does not make it safe — it silences it. Only"
      ylw "  baseline what you have actually reviewed." ;;
    clear)
      local f; f="$(_bl_file "$dir")"
      rm -f "$f" && grn "  baseline cleared for $dir" ;;
    status)
      local f; f="$(_bl_file "$dir")"
      if [ -s "$f" ]; then
        local n; n="$(grep -c . "$f" | tr -d ' ')"
        echo "  baseline: $n accepted finding(s)"
        dim "  $f"
        sed 's/^[0-9a-f]*  /      /' "$f" | head -10
      else
        echo "  baseline: none for $dir"
        dim "  set one with: snare baseline set"
      fi ;;
    *) echo "usage: snare baseline [set|clear|status] [path]" ;;
  esac
}

# Filter a scan's output against the baseline. Prints only new findings.
# Returns 0 when nothing new, 1 when there is something new.
snare_baseline_filter(){
  local dir="$1" out="$2"
  local f; f="$(_bl_file "$dir")"
  [ -s "$f" ] || { echo "$out"; echo "$out" | grep -q '\[!\]' && return 1 || return 0; }

  local new=0 line fp
  while IFS= read -r line; do
    fp="$(printf '%s' "$line" | _bl_fingerprint)"
    grep -q "^$fp  " "$f" 2>/dev/null && continue
    [ "$new" = 0 ] && hdr "New findings (not in baseline)"
    red "  $line"; new=$((new+1))
  done < <(echo "$out" | grep '\[!\]')

  local total; total="$(echo "$out" | grep -c '\[!\]')"
  local accepted=$((total - new))
  if [ "$new" = 0 ]; then
    grn "  nothing new (${accepted} finding(s) previously accepted)"
    return 0
  fi
  echo; dim "  ${accepted} other finding(s) previously accepted"
  return 1
}
