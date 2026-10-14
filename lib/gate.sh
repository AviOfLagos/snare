# shellcheck shell=bash
# gate.sh — scan BEFORE code comes in or runs, for people and for agents.
#
# The incident that prompted this was not a person typing a bad command. It
# was a coding agent doing ordinary work — pull, install, `npm run dev` — in a
# repository that had been poisoned upstream, and nobody finding out until
# days later. The shell shield (shield.sh) cannot cover that well: it wraps
# functions in interactive shells, scans only after `git clone`, never before
# `git pull`, and runs a shallow check that predates every 1.4.x detection.
#
# The gate is one decision: given a shell command, does it bring code in or
# execute it, and if so, is that code clean? It is wired in three ways:
#   snare gate -- <command>    by hand, or by an agent that follows AGENTS.md
#   snare gate --hook          a Claude Code PreToolUse hook: deterministic,
#                              the agent cannot skip it, and exit 2 blocks the
#                              command and hands the findings to the agent
#   snare agents install       writes the hook and the instructions for you
#
# What it does per command:
#   git clone <url>            clones to a quarantine dir first and scans that;
#                              your clone only happens if it is clean
#   git pull / merge / rebase  `git fetch` (which runs nothing), then scans the
#   / checkout / switch <ref>  incoming tree in a throwaway worktree, plus the
#                              forged-force-push check, before anything lands
#   npm/pnpm/yarn/bun/npx/node scans the directory it would run in
#   /next/vite/tsx/turbo/…
#
# Fails CLOSED: a scan that cannot complete blocks the command. Every bypass is
# logged and announced, because a silent bypass is how the original went
# unnoticed.

GATE_LOG="$SNARE_LOGS/gate.log"
GATE_CACHE="$SNARE_HOME/gate-cache"
GATE_TTL=900

# ------------------------------------------------------------ classification
# Python, because this has to understand `cd app && npm i`, `git -C x pull`,
# quoting and `npm --prefix`, and a regex over the raw string gets those wrong
# in exactly the cases that matter. Prints one action per line:
#   tree<TAB>dir             clone<TAB>cwd<TAB>url<TAB>branch
#   pull<TAB>dir<TAB>args…   ref<TAB>dir<TAB>ref        skip<TAB>reason
_gate_py(){
  cat <<'PYGATE'
import os, re, shlex, sys

cmd, cwd = sys.argv[1], sys.argv[2]
ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
WRAPPERS = {"sudo", "time", "env", "nohup", "exec", "command", "builtin",
            "nice", "caffeinate", "stdbuf", "xargs"}
PM = {"npm", "pnpm", "yarn", "bun"}
RUNNERS = {"npx", "bunx", "pnpx", "node", "deno", "next", "vite", "nuxt",
           "tsx", "ts-node", "turbo", "nx", "astro", "remix", "electron"}
# npm-family subcommands that cannot execute repository code. Everything else
# is gated: an unknown subcommand is treated as one that runs things.
SAFE = {"-v", "--version", "version", "-h", "--help", "help", "view", "info",
        "show", "v", "search", "s", "find", "config", "c", "get", "whoami",
        "ls", "list", "la", "ll", "why", "explain", "outdated", "doctor",
        "ping", "prefix", "root", "bin", "owner", "access", "token", "logout",
        "login", "adduser", "team", "profile", "fund", "docs", "home", "bugs",
        "repo", "cache", "audit", "licenses", "store"}
CLONE_VAL = {"-b", "--branch", "--depth", "-o", "--origin", "--reference",
             "-c", "--config", "--template", "--separate-git-dir", "-j",
             "--jobs", "--filter", "-u", "--upload-pack", "--shallow-since",
             "--shallow-exclude", "--server-option", "--bundle-uri"}

def resolve(d, base):
    d = os.path.expanduser(d)
    return os.path.normpath(d if os.path.isabs(d) else os.path.join(base, d))

def segments(line):
    lex = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
    lex.whitespace_split = True
    seg = []
    try:
        for tok in lex:
            if tok and set(tok) <= set(";&|()"):
                if seg:
                    yield seg
                seg = []
            else:
                seg.append(tok)
    except ValueError:
        # Unbalanced quotes. Never fail open on a parse error: fall back to a
        # crude split, which over-matches rather than under-matches.
        for part in re.split(r"&&|\|\||[;|()]", line):
            if part.split():
                yield part.split()
        return
    if seg:
        yield seg

# A heredoc body is DATA unless it is fed to a shell. Reading it as commands
# meant that writing a README with `cat <<EOF` that says "run npm install", or
# a Python script that mentions `git clone`, was blocked as if it ran them.
# Bodies fed to sh/bash/zsh/dash/ksh are shell, and are checked line by line.
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
def shell_lines(text):
    lines = text.splitlines() or [text]
    i = 0
    while i < len(lines):
        line = lines[i]
        yield line
        i += 1
        for m in HEREDOC.finditer(line):
            word = m.group(2)
            before = line[:m.start()].strip().split()
            feeds_shell = bool(before) and os.path.basename(before[-1].lstrip("(")) in SHELLS \
                or any(os.path.basename(w) in SHELLS for w in before[-3:])
            body = []
            while i < len(lines) and lines[i].strip() != word:
                body.append(lines[i]); i += 1
            i += 1   # the terminator
            if feeds_shell:
                for b in body:
                    yield b

# Variables the command itself assigns (S=/path; git clone "$S/x") are
# tracked the way cd is, because shlex does not expand them and git would be
# handed a literal "$S". The gate's own environment is the fallback.
VARS = {}
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
def expand(a):
    a = VAR.sub(lambda m: VARS.get(m.group(1) or m.group(2),
                os.environ.get(m.group(1) or m.group(2), m.group(0))), a)
    return os.path.expanduser(a) if a.startswith("~") else a
def unresolved(a):
    return "$(" in a or "`" in a or bool(VAR.search(a))

# Programs that run another program: the gate looks through them to the
# command they launch. Each was a measured bypass — `sh -c "npm install"`,
# `corepack pnpm install`, `timeout 60 npm install` all ran unchecked.
SHELL_C = {"sh", "bash", "zsh", "dash", "ksh"}
LAUNCHERS = {"corepack", "volta", "nvm", "fnm", "mise", "rtx", "asdf", "proto",
             "cross-env", "cross-env-shell", "dotenv", "dotenvx", "timeout",
             "gtimeout", "watch", "entr", "op", "doppler", "infisical", "with-env"}

out, cur = [], cwd

def handle(argv, depth=0):
    """Classify one simple command. Recurses into sh -c / eval / launchers."""
    global cur
    if depth > 6 or not argv:
        return
    # Leading VAR=value words and wrappers like sudo/env/nohup. The in-command
    # SNARE_SKIP_GATE=1 is deliberately NOT a bypass: the agent writes the
    # command, so honouring it let the agent — or a README that talked it into
    # it — switch the gate off. A bypass has to come from the user.
    while argv and (ENV.match(argv[0]) or os.path.basename(argv[0]) in WRAPPERS):
        argv = argv[1:]
        while argv and argv[0].startswith("-"):
            argv = argv[1:]
    if not argv:
        return
    prog = os.path.basename(argv[0])
    args = argv[1:]

    if prog in ("cd", "pushd"):
        if args and args[0] != "-":
            cur = resolve(args[0], cur)
        elif not args:
            cur = os.path.expanduser("~")
        return

    # sh -c "<script>", bash -lc '<script>' — the script is shell, so check it.
    if prog in SHELL_C:
        for k, a in enumerate(args):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                if k + 1 < len(args):
                    saved = cur
                    for line in shell_lines(args[k + 1]):
                        for seg in segments(line):
                            handle([expand(t) for t in seg], depth + 1)
                    cur = saved
                return
        return
    if prog == "eval":
        for line in shell_lines(" ".join(args)):
            for seg in segments(line):
                handle([expand(t) for t in seg], depth + 1)
        return
    # Launchers: look past their own words to the first program we gate.
    if prog in LAUNCHERS:
        for k, a in enumerate(args):
            b = os.path.basename(a)
            if b in PM or b in RUNNERS or b in ("git", "gh") or b in SHELL_C:
                handle(args[k:], depth + 1)
                return
        return

    if prog == "gh":
        # gh repo clone owner/repo [dir]  ->  a clone of that repository.
        # gh pr checkout <n>              ->  the PR's head, which may come
        #                                     from anyone's fork, lands here.
        if args[:2] == ["repo", "clone"] and len(args) > 2:
            target = args[2]
            url = target if "://" in target or target.startswith("git@") \
                else "https://github.com/%s.git" % target
            out.append("clone\t%s\t%s\t" % (cur, url))
        elif args[:2] == ["pr", "checkout"] and len(args) > 2:
            n = next((a for a in args[2:] if not a.startswith("-")), "")
            n = n.rstrip("/").split("/")[-1]
            if n.isdigit():
                out.append("pull\t%s\torigin\tpull/%s/head" % (cur, n))
            else:
                out.append("unresolved\t%s\tgh pr checkout %s" % (cur, n))
        return

    if prog == "git":
        gdir, i = cur, 0
        while i < len(args) and args[i].startswith("-"):
            if args[i] == "-C" and i + 1 < len(args):
                gdir = resolve(args[i + 1], gdir); i += 2; continue
            if args[i] in ("-c", "--git-dir", "--work-tree", "--namespace") and i + 1 < len(args):
                i += 2; continue
            i += 1
        sub = args[i] if i < len(args) else ""
        rest = args[i + 1:]
        if sub == "clone":
            pos, branch, j = [], "", 0
            while j < len(rest):
                a = rest[j]
                if a in CLONE_VAL and j + 1 < len(rest):
                    if a in ("-b", "--branch"):
                        branch = rest[j + 1]
                    j += 2; continue
                if a.startswith("--branch="):
                    branch = a.split("=", 1)[1]
                if not a.startswith("-"):
                    pos.append(a)
                j += 1
            if pos and unresolved(pos[0]):
                out.append("unresolved\t%s\tgit clone %s" % (gdir, pos[0]))
            elif pos:
                out.append("clone\t%s\t%s\t%s" % (gdir, pos[0], branch))
        elif sub == "pull":
            pos = [a for a in rest if not a.startswith("-")]
            if any(unresolved(a) for a in pos):
                out.append("unresolved\t%s\tgit pull %s" % (gdir, " ".join(pos)))
            else:
                out.append("pull\t%s\t%s" % (gdir, "\t".join(pos[:2])))
        elif sub in ("merge", "rebase", "checkout", "switch", "reset", "cherry-pick"):
            if "--" in rest:
                rest = rest[:rest.index("--")]
            if any(a in ("-b", "-B", "-c", "-C", "--orphan", "--abort",
                         "--continue", "--skip", "--quit") for a in rest):
                return
            for a in rest:
                if a.startswith("-"):
                    continue
                if unresolved(a):
                    out.append("unresolved\t%s\tgit %s %s" % (gdir, sub, a))
                else:
                    out.append("ref\t%s\t%s" % (gdir, a))
        return

    if prog in PM or prog in RUNNERS:
        d, j = cur, 0
        while j < len(args):
            a = args[j]
            if a in ("--prefix", "-C", "--dir", "--cwd") and j + 1 < len(args):
                d = resolve(args[j + 1], cur); j += 2; continue
            for p in ("--prefix=", "--dir=", "--cwd="):
                if a.startswith(p):
                    d = resolve(a[len(p):], cur)
            j += 1
        sub = next((a for a in args if not a.startswith("-")), "")
        if args and set(args) <= {"-v", "--version", "-h", "--help"}:
            return
        if prog in PM and sub in SAFE:
            return
        out.append("tree\t%s" % d)

for line in shell_lines(cmd):
    for argv in segments(line):
        if argv and all(ENV.match(t) for t in argv):
            for t in argv:
                k, v = t.split("=", 1)
                VARS[k] = expand(v)
            continue
        handle([expand(t) for t in argv])

seen = set()
for o in out:
    if o not in seen:
        seen.add(o)
        print(o)
PYGATE
}

# ------------------------------------------------------------------ the cache
# Agents run npm many times in a row. A CLEAN verdict is cached against what
# could change it — HEAD, upstream, the working-tree status, and the files the
# known routes live in (which may be gitignored, so status alone would not
# see a payload dropped into .vscode/). Findings are never cached: a dirty
# tree is rescanned every time, so nothing is stuck once it is cleaned.
_gate_key(){
  ( cd "$1" 2>/dev/null || exit 0
    git rev-parse --git-dir >/dev/null 2>&1 || exit 0
    { pwd -P; echo "$SNARE_VERSION"
      git rev-parse HEAD '@{u}' 2>/dev/null
      git status --porcelain 2>/dev/null
      find . -maxdepth 4 -name node_modules -prune -o -name .git -prune -o \
        \( -name tasks.json -o -name 'settings*.json' -o -name package.json \
           -o -name '*.config.*' -o -name '*.woff*' -o -name '*.ttf' \
           -o -name 'api.js' -o -name 'app.js' -o -name '*.mjs' \) -print 2>/dev/null \
        | sort | while IFS= read -r f; do ls -ln "$f" 2>/dev/null; done
    } | short_hash )
}
_gate_cached(){
  [ -n "$1" ] && [ -f "$GATE_CACHE" ] || return 1
  local t; t="$(grep -m1 "^$1 " "$GATE_CACHE" 2>/dev/null | cut -d' ' -f2)"
  [ -n "$t" ] && [ $(( $(date +%s) - t )) -lt "$GATE_TTL" ]
}
_gate_cache_put(){
  [ -n "$1" ] || return 0
  mkdir -p "$SNARE_HOME" 2>/dev/null
  { grep -v "^$1 " "$GATE_CACHE" 2>/dev/null | tail -200; echo "$1 $(date +%s)"; } \
    > "$GATE_CACHE.tmp" 2>/dev/null && mv "$GATE_CACHE.tmp" "$GATE_CACHE" 2>/dev/null
}

# ------------------------------------------------------------------- scanning
# Each returns 0 clean, 1 findings (printed on stdout), 2 could not scan.
_gate_tree(){ # $1=dir  $2=nocache
  local dir="$1" key="" out rc
  [ -d "$dir" ] || return 0
  [ -z "${2:-}" ] && key="$(_gate_key "$dir")"
  _gate_cached "$key" && return 0
  out="$(cd "$dir" && SNARE_FAST=1 SNARE_NO_UPDATE_CHECK=1 cmd_scan_repo . 2>&1)"; rc=$?
  if [ "$rc" = 0 ]; then _gate_cache_put "$key"; return 0; fi
  out="$(printf '%s\n' "$out" | sed $'s/\033\\[[0-9;]*m//g')"
  if printf '%s\n' "$out" | grep -q '\[!\]'; then
    printf '%s\n' "$out" | awk '/\[!\]/{p=1} /^== /{p=0} p' | grep -v '^[[:space:]]*$' | head -25
    return 1
  fi
  printf '%s\n' "$out" | tail -5
  return 2
}

_gate_clone(){ # $1=cwd $2=url $3=branch
  local url="$2" q rc
  case "$url" in
    /*|*://*|*@*:*) ;;
    *) [ -e "$1/$url" ] && url="$1/$url" ;;
  esac
  q="$(mktemp -d "${SNARE_GATE_TMP:-${TMPDIR:-/tmp}}/snaregate.XXXXXX")" || return 2
  # Cloning runs nothing: hooks are never cloned, and hooksPath is pointed at
  # nothing besides. Submodules are left alone — they are their own clone.
  if ! GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null clone -q --depth 1 \
        --no-recurse-submodules ${3:+-b "$3"} -- "$url" "$q/repo" >"$q/err" 2>&1; then
    echo "could not fetch $2 to check it first:"; sed 's/^/    /' "$q/err" | tail -3
    rm -rf "$q"; return 2
  fi
  # Nothing checked out — the remote's HEAD names a branch that does not
  # exist, so the clone is "empty" even though branches are there. Scanning
  # that empty directory and calling it clean is a verdict about code nobody
  # looked at. Fetch every branch tip and scan each one instead; the next
  # `git checkout <branch>` is exactly what would bring it in.
  if ! git -C "$q/repo" rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
    GIT_TERMINAL_PROMPT=0 git -C "$q/repo" fetch --quiet --depth 1 origin \
      '+refs/heads/*:refs/remotes/origin/*' >/dev/null 2>&1
    local r worst=0 res
    while IFS= read -r r; do
      [ -z "$r" ] && continue
      res="$(_gate_ref "$q/repo" "$r")"; rc=$?
      if [ "$rc" != 0 ]; then
        printf '%s\n' "branch ${r#refs/remotes/origin/}:" "$res"
        # A payload outranks "could not check": report the worse news.
        if [ "$rc" = 1 ]; then worst=1; elif [ "$worst" = 0 ]; then worst=$rc; fi
      fi
    done < <(git -C "$q/repo" for-each-ref --format='%(refname)' refs/remotes/origin 2>/dev/null)
    rm -rf "$q"; return "$worst"
  fi
  _gate_tree "$q/repo" nocache; rc=$?
  rm -rf "$q"; return "$rc"
}

_gate_ref(){ # $1=dir $2=ref — scan a commit's tree without touching the working copy
  local sha q rc
  sha="$(git -C "$1" rev-parse --verify --quiet "$2^{commit}" 2>/dev/null)"
  if [ -z "$sha" ]; then
    # `git checkout feat` / `git switch feat` with only <remote>/feat present
    # creates the branch from the remote copy. That is new code arriving, and
    # "rev-parse failed" used to be read as "not a ref" and let through.
    local dwim
    dwim="$(git -C "$1" for-each-ref --format='%(refname)' "refs/remotes/*/$2" 2>/dev/null | head -1)"
    [ -n "$dwim" ] || return 0
    sha="$(git -C "$1" rev-parse --verify --quiet "$dwim^{commit}" 2>/dev/null)" || return 0
  fi
  [ "$sha" = "$(git -C "$1" rev-parse HEAD 2>/dev/null)" ] && return 0
  q="$(mktemp -d "${SNARE_GATE_TMP:-${TMPDIR:-/tmp}}/snaregate.XXXXXX")" || return 2
  if ! git -C "$1" -c core.hooksPath=/dev/null worktree add --quiet --detach "$q/wt" "$sha" >/dev/null 2>&1; then
    rm -rf "$q"; echo "could not check out $2 to scan it"; return 2
  fi
  _gate_tree "$q/wt" nocache; rc=$?
  git -C "$1" worktree remove --force "$q/wt" >/dev/null 2>&1
  rm -rf "$q"; git -C "$1" worktree prune >/dev/null 2>&1
  return "$rc"
}

_gate_pull(){ # $1=dir  $2.. = remote [branch]
  local dir="$1" ref rc; shift
  git -C "$dir" rev-parse --git-dir >/dev/null 2>&1 || return 0
  # Fetching runs nothing; it is merging the result into your tree that does.
  if [ $# -gt 0 ] && [ -n "$1" ]; then
    GIT_TERMINAL_PROMPT=0 git -C "$dir" fetch --quiet "$@" 2>/dev/null \
      || { echo "could not fetch $* to check it first"; return 2; }
    ref=FETCH_HEAD
  else
    GIT_TERMINAL_PROMPT=0 git -C "$dir" fetch --quiet 2>/dev/null \
      || { echo "could not fetch to check it first"; return 2; }
    ref="$(git -C "$dir" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null)"
    [ -n "$ref" ] || return 0
  fi
  _gate_ref "$dir" "$ref"; rc=$?
  [ "$rc" = 0 ] || return "$rc"
  # In place: this is where the forged-force-push check sees HEAD..@{u}.
  _gate_tree "$dir"
}

# ------------------------------------------------------------------- verdict
_gate_log(){ mkdir -p "$SNARE_LOGS" 2>/dev/null; echo "$(date '+%Y-%m-%dT%H:%M:%S') $*" >> "$GATE_LOG" 2>/dev/null; }

# $1 = command, $2 = cwd. Prints the verdict on stdout. 0 allow, 1 block.
_gate_decide(){
  local cmd="$1" cwd="$2" actions kind a b c rc what out=() blocked=0 cant=0
  actions="$(python3 -c "$(_gate_py)" "$cmd" "$cwd" 2>/dev/null)" || {
    out+=("could not parse the command, so it was not checked")
    cant=1; }
  while IFS="$(printf '\t')" read -r kind a b c _; do
    [ -z "$kind" ] && continue
    local res=""
    case "$kind" in
      tree)   res="$(_gate_tree "$a")"; rc=$? ; what="$a" ;;
      clone)  res="$(_gate_clone "$a" "$b" "$c")"; rc=$? ; what="$b" ;;
      pull)   res="$(_gate_pull "$a" ${b:+"$b"} ${c:+"$c"})"; rc=$? ; what="incoming changes for $a" ;;
      ref)    res="$(_gate_ref "$a" "$b")"; rc=$? ; what="$b in $a" ;;
      unresolved) cant=1
              out+=("could not resolve a value in: $b"
                    "    (built at run time — \$(…), a backtick, or a variable set elsewhere)"
                    "    write the value out literally and the gate can check it"); continue ;;
      *) continue ;;
    esac
    case "$rc" in
      0) ;;
      1) blocked=1; out+=("$what carries a supply-chain payload:" "$res") ;;
      *) cant=1;    out+=("could not finish checking $what:" "$res") ;;
    esac
  done <<< "$actions"
  [ "${#out[@]}" -gt 0 ] && printf '%s\n' "${out[@]}"
  if [ "$blocked" = 1 ] || [ "$cant" = 1 ]; then
    _gate_log "BLOCK $( [ "$blocked" = 1 ] && echo payload || echo unverified ) cwd=$cwd cmd=$cmd"
    return 1
  fi
  return 0
}

_gate_banner(){ # $1=command $2=details $3=payload|unverified
  echo
  if [ "$3" = payload ]; then
    echo "🔥 FIRE ON THE MOUNTAIN — snare blocked this command:"
  else
    echo "⛔ snare could not verify this, so it did not run:"
  fi
  echo "    $1"
  echo
  printf '%s\n' "$2" | sed 's/^/  /'
  echo
  if [ "$3" = payload ]; then
    echo "This code carries a supply-chain payload. Do not run, install, pull,"
    echo "build or open it in an editor. Stop and tell the user now, quoting the"
    echo "findings above. Do not retry it a different way and do not bypass it."
    echo "Next step for the user: snare respond"
  else
    echo "Nothing was run. If the reason above is a network or credentials"
    echo "problem, retry when it is back. If it is a value the gate could not"
    echo "resolve, write it out literally. Only the user can run it unchecked,"
    echo "from their own terminal — an agent cannot switch the gate off."
  fi
}

_gate_killtree(){ # $1 = pid; children first, so none are reparented and missed
  local c
  for c in $(pgrep -P "$1" 2>/dev/null); do _gate_killtree "$c"; done
  kill -TERM "$1" 2>/dev/null
  return 0
}

# Claude Code PreToolUse: JSON on stdin, exit 2 blocks and hands stderr to
# the agent. Anything that is not a shell tool, or not a command that brings
# code in or runs it, exits 0 in a few tens of milliseconds.
_gate_hook(){
  local mode="${1:-}" cmd cwd verdict kind
  # Installed both as a plugin and globally: let the global hook do the work.
  if [ "$mode" = plugin ] && grep -q 'gate --hook' "$HOME/.claude/settings.json" 2>/dev/null; then
    [ -n "${SNARE_HOOK_INPUT:-}" ] || cat >/dev/null
    return 0
  fi
  { IFS= read -r -d '' cmd; IFS= read -r -d '' cwd; } < <(python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if d.get("tool_name") not in ("Bash", "PowerShell"):
    sys.exit(0)
c = (d.get("tool_input") or {}).get("command") or ""
sys.stdout.write(c + "\0" + (d.get("cwd") or "") + "\0")
' 2>/dev/null <<< "${SNARE_HOOK_INPUT:-$(cat)}")
  [ -n "${cmd:-}" ] || return 0
  [ -n "${cwd:-}" ] && [ -d "$cwd" ] || cwd="$PWD"
  # Set in the environment Claude Code was started from — the user's choice,
  # not something the agent can write into a command. Logged and announced.
  if [ -n "${SNARE_SKIP_GATE:-}" ]; then
    _gate_log "BYPASS env cwd=$cwd cmd=$cmd"
    snare_desktop_notify "snare gate is OFF (SNARE_SKIP_GATE): $cmd"
    return 0
  fi
  # Its own deadline, shorter than the hook's timeout. When Claude Code's
  # timeout kills a hook it treats that as a non-blocking error and RUNS the
  # command — so a scan slow enough to time out (a huge clone) would let the
  # command through unchecked. Stopping first, and blocking, keeps it closed.
  local tmp pid n=0 rc budget="${SNARE_GATE_BUDGET:-150}"
  # Everything this run creates — quarantine clones, worktrees — goes under
  # one directory, so a run that is stopped can be cleaned up completely.
  SNARE_GATE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/snaregate-run.XXXXXX")" || return 2
  export SNARE_GATE_TMP
  tmp="$SNARE_GATE_TMP/verdict"
  ( _gate_decide "$cmd" "$cwd" > "$tmp" 2>&1; echo "$?" > "$tmp.rc" ) &
  pid=$!
  while kill -0 "$pid" 2>/dev/null && [ "$n" -lt $(( budget * 5 )) ]; do
    sleep 0.2; n=$((n + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    # The whole tree: the clone is a grandchild, and killing only the direct
    # child left a timed-out `git clone` downloading in the background.
    _gate_killtree "$pid"
    verdict="the scan did not finish within ${budget}s, so nothing was verified"
    rc=1
  else
    wait "$pid" 2>/dev/null
    verdict="$(cat "$tmp" 2>/dev/null)"; rc="$(cat "$tmp.rc" 2>/dev/null || echo 1)"
  fi
  rm -rf "$SNARE_GATE_TMP"
  [ "$rc" = 0 ] && return 0
  printf '%s\n' "$verdict" | grep -q 'supply-chain payload' && kind=payload || kind=unverified
  [ "$kind" = payload ] && snare_desktop_notify "FIRE ON THE MOUNTAIN: an agent tried to run code carrying a payload. Command blocked."
  _gate_banner "$cmd" "$verdict" "$kind" >&2
  return 2
}

cmd_gate(){
  case "${1:-}" in
    --hook)        _gate_hook ;;
    --hook=plugin) _gate_hook plugin ;;
    --)
      shift
      [ $# -gt 0 ] || die "usage: snare gate -- <command>"
      local cmd="$*" verdict kind
      if verdict="$(_gate_decide "$cmd" "$PWD")"; then
        [ -n "$verdict" ] && printf '%s\n' "$verdict"
        grn "  clean — safe to run: $cmd"; return 0
      fi
      printf '%s\n' "$verdict" | grep -q 'supply-chain payload' && kind=payload || kind=unverified
      [ "$kind" = payload ] && snare_desktop_notify "FIRE ON THE MOUNTAIN: snare blocked $cmd"
      _gate_banner "$cmd" "$verdict" "$kind" >&2
      return 1 ;;
    ""|-h|--help)
      echo "usage: snare gate -- <command>    check before running it (0 = clean)"
      echo "       snare gate --hook          Claude Code PreToolUse hook (stdin JSON)" ;;
    *) cmd_gate -- "$@" ;;
  esac
}
