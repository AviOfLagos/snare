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
            "nice", "caffeinate", "stdbuf", "timeout", "gtimeout", "doas"}
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

HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}

# ---------------------------------------------------------------------------
# The rule that makes this fail closed. Two earlier versions tried to list the
# commands that run code, and a review walked past both with commands nobody
# had listed: `if …; then npm install; fi`, `./setup.sh`, `eslint .` (which
# executes the repo's own config), `{npm,install}`, `npm$IFS install`. A shell
# has no end of ways to run code. So the list is now the other way round: the
# programs that provably do NOT run repository code. Inside a git repository,
# anything else — however it is phrased — gets a scan of that repository
# first. Scans are cached, so the cost is paid once per change upstream.
# ---------------------------------------------------------------------------
SAFE_PROGS = {
    "ls", "cat", "head", "tail", "less", "more", "wc", "pwd", "echo", "printf",
    "true", "false", "test", "[", "which", "type", "whoami", "id", "date",
    "uname", "hostname", "printenv", "grep", "egrep", "fgrep", "rg", "ag",
    "fd", "tree", "du", "df", "stat", "file", "diff", "cmp", "comm", "sort",
    "uniq", "cut", "tr", "paste", "join", "column", "nl", "fold", "rev", "tee",
    "basename", "dirname", "realpath", "readlink", "sed", "jq", "yq", "xxd",
    "od", "hexdump", "strings", "sha256sum", "sha1sum", "shasum", "md5",
    "md5sum", "base64", "mkdir", "touch", "cp", "mv", "rm", "rmdir", "ln",
    "chmod", "sleep", "wait", "ps", "pgrep", "lsof", "kill", "pkill", "clear",
    "history", "popd", "dirs", "export", "unset", "set", "shopt", "local",
    "read", "exit", "return", "break", "continue", "trap", "umask", "ulimit",
    "snare", "gh-switch", "unzip", "gzip", "gunzip", "curl",
    "wget", "ssh-keygen", "openssl", "pbcopy", "pbpaste", "say",
    "defaults", "plutil", "mdfind", "free", "top", "uptime", "nproc",
    "seq", "yes", "expr", "bc",
}
# Deliberately NOT safe, though they look harmless: awk (system()), osascript
# (do shell script), tar and zip (--to-command, --use-compress-program, -TT).
GIT_SAFE = {"status", "diff", "log", "show", "branch", "remote", "fetch",
            "rev-parse", "ls-files", "ls-tree", "ls-remote", "blame", "describe",
            "shortlog", "grep", "reflog", "cat-file", "merge-base",
            "for-each-ref", "config", "tag", "count-objects", "version", "help",
            "init", "add", "rev-list", "name-rev", "check-ignore", "var",
            "symbolic-ref", "show-ref", "whatchanged", "range-diff", "notes"}
EDITORS = {"code", "code-insiders", "cursor", "windsurf", "zed", "subl",
           "idea", "webstorm", "open", "xdg-open", "codium", "kiro", "trae"}
RESERVED = {"if", "then", "else", "elif", "fi", "do", "done", "while",
            "until", "{", "}", "!", "time", "function", "coproc", "esac",
            "[[", "]]", "in"}
SHELL_C = SHELLS
LAUNCHERS = {"corepack", "volta", "nvm", "fnm", "mise", "rtx", "asdf", "proto",
             "cross-env", "cross-env-shell", "dotenv", "dotenvx", "timeout",
             "gtimeout", "watch", "entr", "op", "doppler", "infisical", "with-env"}

def match_paren(text, i):
    """Index of the ')' closing the '(' at text[i], quote-aware."""
    depth, q, n = 0, None, len(text)
    while i < n:
        c = text[i]
        if q:
            if c == "\\" and q == '"':
                i += 2; continue
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n

def split_commands(text):
    """Split shell text into simple commands, the way the shell does.

    One pass, tracking quotes. Separators — ; & | ( ) and newline — count only
    OUTSIDE quotes. An earlier version split lines first and parsed quotes
    second, so a quoted string spanning lines (python3 -c "…") was torn into
    fragments that were read as commands of their own. Returns the commands,
    plus the text of every $( ), backtick, <( ) and >( ) — all of which the
    shell executes. Heredoc bodies are consumed here: kept only when a shell
    on the same line reads them (`bash <<EOF`, `cat <<EOF | sh`), dropped as
    data otherwise.
    """
    text = re.sub(r"\\\n[ \t]*", " ", text)          # line continuations
    cmds, subs, buf, line_cmds, heredocs = [], [], [], [], []
    i, n, q = 0, len(text), None

    def flush():
        c = "".join(buf).strip()
        if c:
            cmds.append(c); line_cmds.append(c)
        buf.clear()

    def read_sub(i, opener_len):
        j = match_paren(text, i + opener_len - 1)
        subs.append(text[i + opener_len:j])
        return j + 1

    while i < n:
        c = text[i]
        if q == "'":
            buf.append(c); i += 1
            if c == "'":
                q = None
            continue
        if q == '"':
            if c == "\\" and i + 1 < n:
                buf.append(text[i:i + 2]); i += 2; continue
            if c == '"':
                q = None; buf.append(c); i += 1; continue
            if text.startswith("$(", i) and not text.startswith("$((", i):
                j = read_sub(i, 2); buf.append(text[i:j]); i = j; continue
            if c == "`":
                j = text.find("`", i + 1); j = n if j < 0 else j
                subs.append(text[i + 1:j]); buf.append(text[i:j + 1]); i = j + 1; continue
            buf.append(c); i += 1; continue
        # ---- unquoted
        if c == "\\" and i + 1 < n:
            buf.append(text[i:i + 2]); i += 2; continue
        if c in "'\"":
            q = c; buf.append(c); i += 1; continue
        if c == "#" and (not buf or buf[-1] in " \t"):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("$((", i):
            j = match_paren(text, i + 1); buf.append(text[i:j + 1]); i = j + 1; continue
        if text.startswith("$(", i):
            j = read_sub(i, 2); buf.append(text[i:j]); i = j; continue
        if text.startswith("<(", i) or text.startswith(">(", i):
            j = read_sub(i, 2); buf.append(" /dev/fd/0 "); i = j; continue
        if c == "`":
            j = text.find("`", i + 1); j = n if j < 0 else j
            subs.append(text[i + 1:j]); buf.append(text[i:j + 1]); i = j + 1; continue
        if text.startswith("<<", i) and not text.startswith("<<<", i):
            m = HEREDOC.match(text, i)
            if m:
                heredocs.append(m.group(2)); buf.append(" "); i = m.end(); continue
        # Redirections are not separators: 2>&1, >&2, &>file, <&3.
        if c == "&" and ((buf and buf[-1] in "<>") or text.startswith("&>", i)):
            buf.append(c); i += 1; continue
        if c in ";&|()\n":
            flush()
            if c == "\n" and heredocs:
                words = set()
                for lc in line_cmds:
                    words.update(os.path.basename(w) for w in re.split(r"\s+", lc) if w)
                feeds = bool(words & SHELLS)
                i += 1
                for word in heredocs:
                    start = i
                    while i < n:
                        e = text.find("\n", i); e = n if e < 0 else e
                        if text[i:e].strip() == word:
                            body = text[start:i]; i = e + 1; break
                        i = e + 1
                    else:
                        body = text[start:]
                    if feeds:
                        bc, bs = split_commands(body)
                        cmds.extend(bc); subs.extend(bs)
                heredocs.clear(); line_cmds.clear()
                continue
            if c == "\n":
                line_cmds.clear()
            i += 1; continue
        buf.append(c); i += 1
    flush()
    return cmds, subs

def words(c):
    try:
        return shlex.split(c, posix=True)
    except ValueError:
        return c.split()       # unbalanced quotes: over-match, never under

VARS, ALIASES = {}, {}
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
def expand(a):
    a = VAR.sub(lambda m: VARS.get(m.group(1) or m.group(2),
                os.environ.get(m.group(1) or m.group(2), m.group(0))), a)
    return os.path.expanduser(a) if a.startswith("~") else a
def unresolved(a):
    return "$(" in a or "`" in a or bool(VAR.search(a))

out, cur = [], cwd
IN_FILE = [0]      # >0 while reading a script file the command runs
PRODUCED = set()   # directories an earlier clone in this command creates

def classify(text, depth=0):
    global cur
    if depth > 8:
        return
    cmds, subs = split_commands(text)
    for sub in subs:
        saved = cur
        classify(sub, depth + 1)
        cur = saved
    for c in cmds:
        argv = words(c)
        if argv and all(ENV.match(t) for t in argv):
            for t in argv:
                k, v = t.split("=", 1)
                VARS[k] = expand(v)
            continue
        handle([expand(t) for t in argv], depth)

def unknown():
    out.append("unknown\t%s" % cur)

def cannot(what):
    # At the top level, block: there is nothing to check. Inside a script file
    # the gate reads on the side, "$VAR" everywhere is normal, so fall back to
    # scanning the repository it runs in.
    if IN_FILE[0]:
        unknown()
    else:
        out.append("unresolved\t%s\t%s" % (cur, what))

def handle(argv, depth=0):
    global cur
    if depth > 8 or not argv:
        return
    while argv:
        a0 = argv[0]
        if a0 in ("for", "select", "case"):
            return                        # loop/case headers; bodies come next
        if a0 in RESERVED or ENV.match(a0):
            argv = argv[1:]; continue
        b0 = os.path.basename(a0)
        if b0 == "command" and len(argv) > 1 and argv[1] in ("-v", "-V"):
            return                        # a lookup, not a run
        if b0 in WRAPPERS:
            argv = argv[1:]
            while argv and argv[0].startswith("-"):
                argv = argv[1:]
            if b0 == "timeout" and argv and re.match(r"^[0-9.]+[smhd]?$", argv[0]):
                argv = argv[1:]
            continue
        break
    if not argv:
        return
    raw = argv[0]
    # A program name the gate cannot read for certain — a variable, a brace
    # or glob expansion — could be anything.
    # (Scanned, not blocked: "$EDITOR" or "$PYTHON" in a clean repository is
    # fine. A clone URL or ref it cannot read IS blocked — see cannot().)
    if unresolved(raw) or (re.search(r"[{}*?\[\]]", raw) and raw not in ("[", "[[")):
        unknown(); return
    prog = os.path.basename(raw)
    args = argv[1:]

    if prog in ALIASES:
        handle(shlex.split(ALIASES[prog]) + args, depth + 1); return
    if prog == "alias":
        for a in args:
            if "=" in a:
                k, v = a.split("=", 1); ALIASES[k] = v
        return
    if prog in ("cd", "pushd"):
        if args and args[0] != "-":
            cur = resolve(args[0], cur)
        elif not args:
            cur = os.path.expanduser("~")
        return

    # sh -c "<script>", bash -lc '<script>'
    if prog in SHELL_C:
        for k, a in enumerate(args):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                if k + 1 < len(args):
                    saved = cur; classify(args[k + 1], depth + 1); cur = saved
                return
    if prog == "eval":
        saved = cur; classify(" ".join(args), depth + 1); cur = saved
        return
    if prog in LAUNCHERS:
        for k, a in enumerate(args):
            b = os.path.basename(a)
            if b in PM or b in RUNNERS or b in ("git", "gh") or b in SHELL_C:
                handle(args[k:], depth + 1); return
        unknown(); return

    # Running a script file: what it runs is what matters, so read it.
    script = None
    if prog in SHELL_C and args and not args[0].startswith("-"):
        script = args[0]
    elif prog in ("source", "."):
        script = args[0] if args else None
    elif raw.startswith(("./", "../", "/", "~")) or prog.endswith(".sh"):
        script = raw
    if script:
        unknown()
        path = resolve(script, cur)
        try:
            if os.path.isfile(path) and os.path.getsize(path) < 200000:
                text = open(path, errors="replace").read()
                first = text.split("\n", 1)[0]
                if not first.startswith("#!") or any(s in first for s in SHELLS):
                    saved = cur; IN_FILE[0] += 1
                    classify(text, depth + 1)
                    IN_FILE[0] -= 1; cur = saved
        except Exception:
            pass
        return

    if prog == "gh":
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
                cannot("gh pr checkout %s" % n)
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
        if sub in GIT_SAFE or sub == "" or (sub == "stash" and rest[:1] in (["list"], ["show"])) \
           or (sub == "worktree" and rest[:1] == ["list"]):
            return
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
                cannot("git clone %s" % pos[0])
            elif pos:
                src = pos[0]
                local = "://" not in src and not re.match(r"^[^/]+@[^:]+:", src)
                srcpath = resolve(src, gdir) if local else ""
                if not (local and any(srcpath == p or srcpath.startswith(p + os.sep)
                                      for p in PRODUCED)):
                    rec = "1" if any(a in ("--recurse-submodules", "--recursive")
                                     or a.startswith("--recurse-submodules=") for a in rest) else ""
                    out.append("clone\t%s\t%s\t%s\t%s" % (gdir, src, branch, rec))
                dest = pos[1] if len(pos) > 1 else \
                    os.path.basename(src.rstrip("/")).rsplit(".git", 1)[0]
                PRODUCED.add(resolve(dest, gdir))
            return
        if sub == "pull":
            pos = [a for a in rest if not a.startswith("-")]
            if any(unresolved(a) for a in pos):
                cannot("git pull %s" % " ".join(pos))
            else:
                out.append("pull\t%s\t%s" % (gdir, "\t".join(pos[:2])))
            return
        if sub in ("merge", "rebase", "checkout", "switch", "reset", "cherry-pick"):
            if "--" in rest:
                rest = rest[:rest.index("--")]
            if not any(a in ("-b", "-B", "-c", "-C", "--orphan", "--abort",
                             "--continue", "--skip", "--quit") for a in rest):
                for a in rest:
                    if a.startswith("-"):
                        continue
                    if unresolved(a):
                        cannot("git %s %s" % (sub, a))
                    else:
                        out.append("ref\t%s\t%s" % (gdir, a))
        if sub == "submodule" and "update" in rest:
            out.append("submodules\t%s" % gdir)
            return
        # commit, push, am, stash pop, and the rest: git hooks — husky's
        # included, installed by the repo's own `prepare` script — run here.
        cur_saved = cur; cur = gdir; unknown(); cur = cur_saved
        return

    if prog in EDITORS:
        # Opening a folder in an editor is exactly what fires a folderOpen task.
        targets = [a for a in args if not a.startswith("-")]
        for t in targets or ["."]:
            out.append("tree\t%s" % resolve(t, cur))
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
        return

    if prog == "find" and any(a in ("-exec", "-execdir", "-ok", "-okdir") for a in args):
        k = next(i for i, a in enumerate(args) if a in ("-exec", "-execdir", "-ok", "-okdir"))
        handle([a for a in args[k + 1:] if a not in (";", "{}", "+", "\;")], depth + 1)
        return
    if prog == "xargs":
        while args and args[0].startswith("-"):
            args = args[1:]
        handle(args, depth + 1); return
    if prog in SAFE_PROGS:
        return
    # Everything else — eslint, jest, postcss, python, make, a function the
    # command just defined — could run repository code. Check the repository.
    unknown()

classify(cmd)

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
      # Not `git status`: the agent's own edits to src/ would invalidate the
      # cache after every keystroke. Payloads arrive through what changes
      # HEAD or through the route files below, gitignored ones included.
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

_gate_clone(){ # $1=cwd $2=url $3=branch $4=1 when the clone recurses into submodules
  local url="$2" q rc sub=()
  # --recurse-submodules brings in code from other repositories too; the gate
  # has to see what the real clone will.
  [ -n "${4:-}" ] && sub=(--recurse-submodules --shallow-submodules)
  case "$url" in
    /*|*://*|*@*:*) ;;
    *) [ -e "$1/$url" ] && url="$1/$url" ;;
  esac
  q="$(mktemp -d "${SNARE_GATE_TMP:-${TMPDIR:-/tmp}}/snaregate.XXXXXX")" || return 2
  # Cloning runs nothing: hooks are never cloned, and hooksPath is pointed at
  # nothing besides. Submodules are left alone — they are their own clone.
  if ! GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null clone -q --depth 1 \
        ${sub[@]+"${sub[@]}"} ${3:+-b "$3"} -- "$url" "$q/repo" >"$q/err" 2>&1; then
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

_gate_submodules(){ # $1=dir — each submodule at the commit the repo pins
  local dir="$1" path url sha q rc worst=0 res
  [ -f "$dir/.gitmodules" ] || return 0
  while IFS=' ' read -r key path; do
    [ -z "$path" ] && continue
    url="$(git -C "$dir" config -f .gitmodules --get "${key%.path}.url" 2>/dev/null)"
    sha="$(git -C "$dir" ls-tree HEAD -- "$path" 2>/dev/null | awk '{print $3}')"
    [ -n "$url" ] && [ -n "$sha" ] || continue
    case "$url" in ./*|../*) url="$(git -C "$dir" remote get-url origin 2>/dev/null)/$url" ;; esac
    q="$(mktemp -d "${SNARE_GATE_TMP:-${TMPDIR:-/tmp}}/snaregate.XXXXXX")" || return 2
    if git init -q "$q/s" && GIT_TERMINAL_PROMPT=0 git -C "$q/s" -c core.hooksPath=/dev/null \
         fetch -q --depth 1 -- "$url" "$sha" >/dev/null 2>&1 \
       && git -C "$q/s" -c core.hooksPath=/dev/null checkout -q FETCH_HEAD >/dev/null 2>&1; then
      res="$(_gate_tree "$q/s" nocache)"; rc=$?
    else
      res="could not fetch submodule $path ($url) at $sha"; rc=2
    fi
    rm -rf "$q"
    if [ "$rc" != 0 ]; then
      printf '%s\n' "submodule $path:" "$res"
      if [ "$rc" = 1 ]; then worst=1; elif [ "$worst" = 0 ]; then worst=$rc; fi
    fi
  done < <(git -C "$dir" config -f .gitmodules --get-regexp '^submodule\..*\.path$' 2>/dev/null)
  return "$worst"
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
  local cmd="$1" cwd="$2" actions kind a b c d rc what seen_top="" out=() blocked=0 cant=0
  actions="$(python3 -c "$(_gate_py)" "$cmd" "$cwd" 2>/dev/null)" || {
    out+=("could not parse the command, so it was not checked")
    cant=1; }
  while IFS="$(printf '\t')" read -r kind a b c d; do
    [ -z "$kind" ] && continue
    local res=""
    case "$kind" in
      tree)
              # Outside a repository there is no committed payload to find,
              # and a package manager reads only this directory's own
              # package.json. Scanning a bare /tmp recursively took 8s and
              # reported code in unrelated subdirectories as this command's.
              if ! git -C "$a" rev-parse --git-dir >/dev/null 2>&1 && [ ! -f "$a/package.json" ]; then
                continue
              fi
              res="$(_gate_tree "$a")"; rc=$? ; what="$a" ;;
      clone)  res="$(_gate_clone "$a" "$b" "$c" "$d")"; rc=$? ; what="$b" ;;
      pull)   res="$(_gate_pull "$a" ${b:+"$b"} ${c:+"$c"})"; rc=$? ; what="incoming changes for $a" ;;
      ref)    res="$(_gate_ref "$a" "$b")"; rc=$? ; what="$b in $a" ;;
      unknown)
              # Something that may run repository code, by a route no list
              # can name. Scan the repository it runs in — once per repo.
              local top; top="$(git -C "$a" rev-parse --show-toplevel 2>/dev/null)"
              [ -n "$top" ] || continue          # not a repository: no committed payload
              case " $seen_top " in *" $top "*) continue ;; esac
              seen_top="$seen_top $top"
              res="$(_gate_tree "$top")"; rc=$?; what="$top" ;;
      submodules) res="$(_gate_submodules "$a")"; rc=$?; what="submodules of $a" ;;
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
