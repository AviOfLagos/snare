# shellcheck shell=bash
# selftest.sh — prove the detector actually detects. Closes #5.
#
# Every defect in #2 produced a FALSE CLEAN and shipped undetected, because
# nothing ever asserted that a known-bad sample gets flagged. This builds a
# scratch repo of known-bad and known-good samples, runs the real scanner
# against it, and fails loudly on any mismatch.

ST_PASS=0; ST_FAIL=0

_st_ok(){   grn "  PASS  $*"; ST_PASS=$((ST_PASS+1)); }
_st_bad(){  red "  FAIL  $*"; ST_FAIL=$((ST_FAIL+1)); }

# $1 = human label, $2 = expect (hit|clean), $3 = grep pattern, $4 = scan output
#
# Only [!] lines count as findings. A [~] note (e.g. "this line is long") is
# informational and must NOT fail a known-good sample — minified bundles are
# legitimately long, and treating that as a finding is how you train people to
# ignore the output.
_st_expect(){
  local label="$1" expect="$2" pat="$3" out="$4"
  local findings; findings="$(echo "$out" | grep '\[!\]')"
  if echo "$findings" | grep -qE "$pat"; then
    [ "$expect" = hit ] && _st_ok "$label" || _st_bad "$label (reported as a finding, should be clean)"
  else
    [ "$expect" = clean ] && _st_ok "$label" || _st_bad "$label (NOT flagged — false clean)"
  fi
}

cmd_selftest(){
  local keep=0
  [ "${1:-}" = "--keep" ] && keep=1

  # GNU mktemp requires the XXXXXX template; BSD/macOS does not.
  local T; T="$(mktemp -d "${TMPDIR:-/tmp}/snareselftest.XXXXXX")" \
    || { red "  cannot create a temp directory"; return 1; }
  hdr "snare selftest"
  echo "  scratch: $T"

  ( cd "$T" || exit 1
    git init -q . 2>/dev/null
    git config user.email selftest@snare.local 2>/dev/null
    git config user.name  "snare selftest"     2>/dev/null

    # ---- known BAD samples -------------------------------------------------
    # 1. plain IOC string in a tracked file
    local ioc; ioc="$(grep -m1 -oE '0x[a-fA-F0-9]{40}' "$IOCS" 2>/dev/null)"
    [ -z "$ioc" ] && ioc='0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a'
    printf 'const c2 = "%s";\n' "$ioc" > bad_ioc.js

    # 2. build config with the payload hidden past a whitespace run.
    #    Deliberately SHORT (~700 chars) — the old `length > 1500` heuristic
    #    missed exactly this, so the test must be shorter than that threshold.
    printf 'export default config;%*sglobal.i="A8-0000-0";var u=new URL("http://1.2.3.4:443/0x/ls");\n' \
      600 '' > postcss.config.mjs

    # 3. fake font: JavaScript wearing a .woff2 extension
    printf 'process.mainModule.require("child_process").spawn("node");\n' > public_fake.woff2

    # 4. editor auto-execution vector
    mkdir -p .vscode
    cat > .vscode/tasks.json <<'JSON'
{ "version": "2.0.0",
  "tasks": [ { "label": "eslint-check", "type": "shell",
    "command": "node ./public_fake.woff2", "hide": true,
    "runOptions": { "runOn": "folderOpen" } } ] }
JSON

    # ---- known GOOD samples (must NOT be flagged) --------------------------
    # 5. genuine TrueType font: magic 00 01 00 00. bash cannot hold NUL, which
    #    is precisely why the old string-compare could never match it.
    printf '\x00\x01\x00\x00' > real_font.ttf
    head -c 2000 /dev/zero 2>/dev/null >> real_font.ttf

    # 6. genuine woff2
    printf 'wOF2' > real_font2.woff2
    head -c 500 /dev/zero 2>/dev/null >> real_font2.woff2

    # 7. long minified-but-clean JS: long line, no whitespace-hidden payload
    { printf 'var a=1;'; for i in $(seq 1 400); do printf 'var x%d=%d;' "$i" "$i"; done; printf '\n'; } > minified.js

    git add -A >/dev/null 2>&1
    git commit -qm "selftest fixtures" >/dev/null 2>&1
  )

  local out; out="$(cmd_scan_repo "$T" 2>&1)"

  hdr "Known-bad samples (must be flagged)"
  _st_expect "IOC string in tracked file"            hit   'bad_ioc\.js'          "$out"
  _st_expect "payload hidden past whitespace (700c)" hit   'postcss\.config\.mjs' "$out"
  _st_expect "fake .woff2 (no wOF2 magic)"           hit   'public_fake\.woff2'   "$out"
  _st_expect "tasks.json runOn:folderOpen"           hit   'folderOpen'           "$out"

  hdr "Known-good samples (must NOT be flagged)"
  _st_expect "genuine .ttf (00 01 00 00 magic)"      clean 'real_font\.ttf'       "$out"
  _st_expect "genuine .woff2 (wOF2 magic)"           clean 'real_font2\.woff2'    "$out"
  _st_expect "long but clean minified JS"            clean 'minified\.js'         "$out"

  hdr "Scanner self-exclusion"
  local selfout; selfout="$(cmd_scan_repo "$SNARE_ROOT" 2>&1)"
  _st_expect "snare's own lib/ not self-reported"    clean 'lib/scan\.sh'         "$selfout"

  if [ "$keep" = 1 ]; then dim "  kept: $T"; else rm -rf "$T"; fi

  hdr "RESULT"
  if [ "$ST_FAIL" -eq 0 ]; then
    grn "  all $ST_PASS checks passed — detection is working"
    return 0
  fi
  red "  $ST_FAIL of $((ST_PASS+ST_FAIL)) checks FAILED"
  red "  detection is broken — do not trust a 'clean' result until this passes"
  return 1
}
