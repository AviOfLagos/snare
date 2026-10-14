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

# Every git call the gate makes runs INSIDE the repository it is checking,
# and git obeys that repository's .git/config. A directory that arrives with
# its own .git — an archive, a copied tree — can set core.fsmonitor, a
# credential helper, an ssh command or a per-remote upload-pack, and the
# first `git status` runs it. The gate must never execute what it is checking,
# so these are pinned for every call it makes.
GATE_GIT=(git -c core.fsmonitor=false -c core.hooksPath=/dev/null
          -c core.sshCommand=ssh -c credential.helper= -c core.pager=cat
          -c protocol.ext.allow=never -c core.untrackedCache=false
          -c diff.external= -c core.askPass=)
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
SELFROOT = os.path.realpath(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else ""
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
    text = re.sub(r"\\\n", "", text)   # bash deletes it: n\<newline>pm is npm
    cmds, subs, buf, line_cmds, heredocs = [], [], [], [], []
    i, n, q = 0, len(text), None
    piped = [False]          # the NEXT command reads from a pipe

    def flush(sep=""):
        c = "".join(buf).strip()
        if c:
            cmds.append(("\x00PIPE " if piped[0] else "") + c); line_cmds.append(c)
        buf.clear()
        piped[0] = sep == "|"

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
            flush("|" if c == "|" and not text.startswith("||", i) and text[i - 1:i] != "|" else "")
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
PIPED = [False]    # the command being handled reads a pipe
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
        PIPED[0] = c.startswith("\x00PIPE ")
        argv = words(c[6:] if PIPED[0] else c)
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
        if ENV.match(a0) and re.match(r"^(GIT_[A-Z_]*|PAGER|LESSOPEN|LESSCLOSE|EDITOR|VISUAL|BROWSER|NODE_OPTIONS|BASH_ENV|ENV|PROMPT_COMMAND|LD_PRELOAD|DYLD_[A-Z_]*)=", a0):
            unknown()     # names a program something here will start
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

    # Approving a block or switching the gate off is the user's decision. An
    # agent that tries — directly, through sh -c, eval, a script — is refused.
    # `snare respond` approves and cleans too, so it is the person's as well
    # (its read-only --status is not).
    if prog == "snare" and (args[:2] in (["gate", "allow"], ["gate", "forget"])
                            or args[:2] == ["agents", "uninstall"]
                            or (args[:1] == ["respond"] and args[1:] != ["--status"])):
        out.append("refuse\t%s\tsnare %s" % (cur, " ".join(args[:2]))); return
    # Writing the user's real approval or opt-out files. Reading them is fine,
    # and so is a different SNARE_HOME (a test, a fixture); a write to the
    # real ones — a redirect, tee, cp, mv, rm, sed -i — is the agent deciding.
    state = os.path.realpath(os.path.expanduser(os.environ.get("SNARE_HOME") or "~/.snare"))
    home = os.path.expanduser("~")
    # Any path into the state DIRECTORY counts, not only the named files —
    # replacing gate-cache or the whole directory is the same decision.
    def real_state(t):
        t = os.path.expanduser(t.strip("'\""))
        if not t:
            return False
        try:
            p = os.path.realpath(resolve(t, cur))
        except Exception:
            return False
        return p == state or p.startswith(state + os.sep)
    # Spellings of the state directory that can appear inside a larger token:
    # a python -c string, a node -e string, an sh -c script.
    spellings = {state, "~/.snare", "$HOME/.snare", "${HOME}/.snare"}
    if state.startswith(home + os.sep):
        spellings.add("~" + state[len(home):])
    writers = {"tee", "cp", "mv", "ln", "rm", "truncate", "dd", "install", "rsync",
               "touch", "chmod", "unlink", "sed", "perl", "python", "python3", "node",
               "ruby", "php", "osascript", "awk", "gawk", "deno", "bun", "tar", "unzip"}
    for k, a in enumerate(argv):
        # A redirect anywhere in a token: `echo x>~/.snare/gate-allow` is one
        # word to the tokenizer, and only checking its start missed it.
        for m in re.finditer(r"\d?&?>>?\|?", a):
            target = a[m.end():].split(">")[0]
            if real_state(target):
                out.append("refuse\t%s\twriting snare's own state" % cur); return
        if k > 0 and argv[k - 1] in (">", ">>", "1>", "2>", "&>", ">|") and real_state(a):
            out.append("refuse\t%s\twriting snare's own state" % cur); return
        if prog in writers and (real_state(a) or any(sp in a for sp in spellings)):
            out.append("refuse\t%s\twriting snare's own state" % cur); return
    if prog == "export" and any(re.match(r"^(GIT_[A-Z_]*|PAGER|LESSOPEN|EDITOR|VISUAL|NODE_OPTIONS|BASH_ENV|ENV|PROMPT_COMMAND|LD_PRELOAD|DYLD_[A-Z_]*)=", a) for a in args):
        unknown(); return
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
    if prog in SHELL_C and PIPED[0] and not any(a.startswith("-") and "c" in a[1:] for a in args) \
            and not (args and not args[0].startswith("-")):
        cannot("a shell running whatever is piped into it (curl … | sh)"); return
    script = None
    if prog in SHELL_C and args and not args[0].startswith("-"):
        script = args[0]
    elif prog in ("source", "."):
        script = args[0] if args else None
    elif raw.startswith(("./", "../", "/", "~")) or prog.endswith(".sh"):
        script = raw
    if script and os.path.basename(script) == "snare":
        handle(["snare"] + (args[1:] if prog in SHELL_C or prog in ("source", ".") else args), depth + 1)
        return
    if script:
        unknown()
        path = resolve(script, cur)
        # snare's own install is never read as untrusted code: a harness that
        # sources snare's lib/ is not writing snare's state.
        rp_ = os.path.realpath(path)
        if SELFROOT and (rp_ == SELFROOT or rp_.startswith(SELFROOT + os.sep)):
            return
        if IN_FILE[0] >= 1:
            # A script a script runs or sources is classified in full. Sourcing
            # RUNS every top-level line of the library — an earlier version kept
            # only refusals from it, so `bash run.sh` sourcing a lib that clones
            # and installs another repository checked neither. Function bodies
            # are read too; that over-reads, which costs a scan, not a miss.
            try:
                if os.path.isfile(path) and os.path.getsize(path) < 200000:
                    saved = cur; IN_FILE[0] += 1
                    classify(open(path, errors="replace").read(), depth + 1)
                    IN_FILE[0] -= 1; cur = saved
            except Exception:
                pass
            return
        if not os.path.exists(path):
            # Written by an earlier part of this same command — a download, a
            # heredoc, a cp. It cannot be read before it exists.
            cannot("%s, which does not exist until this command creates it" % script); return
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
        # `git -c core.pager='npm install' log` runs the pager; -c can set any
        # program git will start (pager, editor, sshCommand, fsmonitor, diff
        # drivers, aliases with !). --ext-diff and difftool start one too.
        # `git config core.hooksPath …`, `alias.x '!…'` and friends arm a
        # program for a later command; only reading config is safe.
        if sub == "config" and not any(a in ("--get", "--get-all", "--get-regexp", "-l", "--list",
                                             "--show-origin", "--show-scope") for a in rest) \
                and len([a for a in rest if not a.startswith("-")]) >= 2:
            unknown(); return
        if any(a.startswith(("--upload-pack", "--receive-pack", "--exec")) or a == "-u" for a in rest):
            unknown(); return
        configured = any(a == "-c" or a.startswith("-c") and len(a) > 2 for a in args[:i]) \
            or any(a in ("--ext-diff", "--textconv", "--open-files-in-pager", "-O") or
                   a.startswith(("--open-files-in-pager=", "--exec=")) for a in rest)
        if not configured and (sub in GIT_SAFE or sub == "" or
                               (sub == "stash" and rest[:1] in (["list"], ["show"])) or
                               (sub == "worktree" and rest[:1] == ["list"])):
            return
        if sub == "clone" and any(a.startswith(("--upload-pack", "-u", "--template", "--config", "-c")) for a in rest):
            cannot("git clone with an option that runs or installs a program"); return
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
    # Read-only programs that can still run a command through a flag. Each was
    # a way past the safe list: rg --pre, fd --exec, sort --compress-program,
    # git -c core.pager=…, and an environment variable that names a command.
    EXEC_FLAGS = {"rg": ("--pre",), "fd": ("-x", "--exec", "-X", "--exec-batch"),
                  "sort": ("--compress-program",), "less": (), "more": ()}
    if prog in EXEC_FLAGS and any(a == f or a.startswith(f + "=") for a in args
                                   for f in EXEC_FLAGS[prog]):
        unknown(); return
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
# The gate's check. Not `snare scan repo`: that greps every file, and on a
# real repository holding a few agent worktrees under .claude/worktrees it ran
# past the 150s deadline — so every command an agent ran there was blocked as
# unverified. This walks only where this campaign executes from, prunes
# node_modules, build output and other worktrees, and reports each finding
# as the file, the line and what is suspected, so a person can look at it.
_gate_routes_py(){
  cat <<'PYROUTES'
import hashlib, json, os, re, subprocess, sys, time
root, litf, rx, cachef, allowf, ver, nocache, selfroot = sys.argv[1:9]
root = os.path.realpath(root)
# snare's own source quotes every marker it detects, so its install is
# exempt — but only its install. A repository that merely ships a .snare-tool
# file was exempted too, which is a one-file way past the gate.
if os.path.exists(os.path.join(root, ".snare-tool")) and root == os.path.realpath(selfroot):
    sys.exit(0)

PRUNE = {"node_modules", ".git", ".next", ".nuxt", ".turbo", ".svelte-kit",
         ".output", ".vercel", ".cache", "coverage", ".parcel-cache", ".yarn",
         "bower_components", "Pods", ".gradle", ".venv", "venv", "__pycache__",
         "target", ".terraform"}
PRUNE_REL = {".claude/worktrees", ".kilo/worktrees", ".cursor/worktrees",
             ".codex/worktrees", ".git/worktrees"}
MAXDEPTH, MAXDIRS = 6, 20000
CONFIG = re.compile(r"(^|\.)(config|rc)\.(js|mjs|cjs|ts|mts|cts)$|^\.(babel|eslint|prettier)rc(\.(js|cjs|mjs))?$")
FONT = re.compile(r"\.(woff2?|ttf|otf)$", re.I)
AGENT = re.compile(r"(^|/)\.(claude|cursor|gemini|codex)/([^/]*/)?settings[^/]*\.json$")
DROPPERS = {".claude/setup.mjs", ".vscode/setup.mjs", ".claude/math_init.js",
            ".claude/Math_Symbol.js", ".vscode/math_init.js"}
OBF = re.compile(r"_0x[0-9a-f]{4,}|\\u00[0-9a-fA-F]{2}|eval\(|atob\(|child_process|global\[['\"]|\['[0-9a-f]{8,}',\s*'[0-9a-f]{8,}'")
HIDDEN = re.compile(r"\S[ \t]{50,}\S")
WSFIRST = re.compile(r"^[ \t]{50,}\S")
BAD = re.compile(r"setup\.mjs|math_init|Math_Symbol|\bnode\b[^|;&\n]*\s--?(e|p|pe|ep|eval|print)(\s|=|$)|curl|wget|base64|\beval\b|child_process|\|\s*(sh|bash)|https?://\d+\.\d+\.\d+\.\d+|atob\(|Invoke-WebRequest|EncodedCommand", re.I)
lits = [l.rstrip("\n") for l in open(litf, errors="replace") if l.strip()] if os.path.exists(litf) else []
try:
    IOC = re.compile(rx.replace("[[:space:]]", r"\s")) if rx else None
except re.error:
    IOC = None

# ---- walk: collect the files the known routes live in
routes, ndirs, truncated = [], 0, False
for dirpath, dirnames, filenames in os.walk(root):
    rel = os.path.relpath(dirpath, root)
    depth = 0 if rel == "." else rel.count(os.sep) + 1
    keep = []
    for d in dirnames:
        r = d if rel == "." else os.path.join(rel, d)
        if d in PRUNE or r in PRUNE_REL or depth + 1 > MAXDEPTH or os.path.islink(os.path.join(dirpath, d)):
            continue
        keep.append(d)
    dirnames[:] = keep
    ndirs += 1
    if ndirs > MAXDIRS:
        truncated = True; break
    for f in filenames:
        r = f if rel == "." else os.path.join(rel, f)
        rp = r.replace(os.sep, "/")
        if (f == "package.json" or CONFIG.search(f) or FONT.search(f) or AGENT.search(rp)
                or (rp.startswith(".husky/") and not rp.startswith(".husky/_/"))
                or rp.endswith(".vscode/tasks.json") or rp in DROPPERS
                or (depth == 0 and re.search(r"\.(c|m)?js$", f))
                or (depth == 0 and f == ".gitignore")):
            routes.append(rp)

PIN = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
       "-c", "credential.helper=", "-c", "core.sshCommand=ssh", "-c", "protocol.ext.allow=never"]
SRC = re.compile(r"\.(c|m)?(j|t)sx?$")
srcfiles = []
for dirpath, dirnames, filenames in os.walk(root):
    rel = os.path.relpath(dirpath, root)
    depth = 0 if rel == "." else rel.count(os.sep) + 1
    dirnames[:] = [d for d in dirnames if d not in PRUNE and depth + 1 <= 10
                   and (d if rel == "." else os.path.join(rel, d)) not in PRUNE_REL
                   and not os.path.islink(os.path.join(dirpath, d))]
    for f in filenames:
        if SRC.search(f):
            srcfiles.append((f if rel == "." else os.path.join(rel, f)).replace(os.sep, "/"))
    if len(srcfiles) > 6000:
        break

def git(*a):
    try:
        return subprocess.run(["git"] + PIN + ["-C", root] + list(a), capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""

# ---- cache: valid while nothing a route lives in has changed
key_src = [ver, root, git("rev-parse", "HEAD"), git("rev-parse", "@{u}")]
try:
    key_src.append(str(os.stat(allowf).st_mtime_ns))
except OSError:
    pass
for r in sorted(set(routes) | set(srcfiles[:6000])):
    try:
        st = os.stat(os.path.join(root, r)); key_src.append("%s %d %d" % (r, st.st_size, st.st_mtime_ns))
    except OSError:
        pass
key = hashlib.sha256("\n".join(key_src).encode()).hexdigest()[:24]
if nocache != "1" and os.path.exists(cachef):
    now = time.time()
    for ln in open(cachef):
        k, _, t = ln.strip().partition(" ")
        if k == key and t.isdigit() and now - int(t) < 900:
            sys.exit(0)

allowed = set()
if os.path.exists(allowf):
    for ln in open(allowf):
        if ln.strip() and not ln.startswith("#"):
            allowed.add(ln.split()[0])

findings = []
def find(rp, line, what, excerpt, data):
    fp = hashlib.sha256(("%s\0%s\0%s" % (rp, what, hashlib.sha256(data).hexdigest())).encode()).hexdigest()[:16]
    if fp in allowed:
        return
    findings.append((rp, line, what, excerpt.replace("\t", " ")[:140], fp))

def short(s):
    return re.sub(r"\s+", " ", s).strip()

def lines_of(data):
    return data.decode("utf-8", "replace").split("\n")

def code_scan(rp, data, src=False):
    """Hidden payloads and markers. src=True is the wider source pass, where
    ordinary code is far commoner than a payload, so a hidden tail must look
    obfuscated and the long-line rule is off (minified bundles are legitimate)."""
    for n, ln in enumerate(lines_of(data), 1):
        stripped = ln.lstrip()
        comment = stripped.startswith(("*", "//", "#"))
        m = HIDDEN.search(ln)
        if m and not comment and len(ln) > 120:
            run = len(ln[m.start() + 1:]) - len(ln[m.start() + 1:].lstrip())
            tail = ln[m.start() + 1 + run:]
            trailing_comment = tail.lstrip().startswith(("//", "/*", "*", "#"))
            if not trailing_comment and (not src or OBF.search(tail) or len(tail) > 400):
                find(rp, n, "code hidden after %d spaces/tabs on this line" % run,
                     "…" + short(tail)[:100], data); return
        if WSFIRST.match(ln) and len(ln) > 200:
            find(rp, n, "the line opens with %d spaces/tabs, then code" % (len(ln) - len(stripped)),
                 short(stripped)[:100], data); return
        lo = ln.lower()
        hit = next((l for l in lits if l.lower() in lo), None)
        if not hit and IOC and not comment:
            mm = IOC.search(ln); hit = mm.group(0) if mm else None
        if hit and not comment:
            find(rp, n, "known campaign marker: %s" % hit[:40], short(ln)[:100], data); return
        if not src and len(ln) > 5000 and OBF.search(ln):
            find(rp, n, "one %d-character line of obfuscated code" % len(ln), short(ln)[:80], data); return

def jsonc(data):
    s = data.decode("utf-8-sig", "replace")
    out, i, n, q = [], 0, len(s), False
    while i < n:
        c = s[i]
        if q:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(s[i + 1]); i += 2; continue
            if c == '"':
                q = False
            i += 1; continue
        if c == '"':
            q = True; out.append(c); i += 1; continue
        if s.startswith("//", i):
            while i < n and s[i] != "\n":
                i += 1
            continue
        if s.startswith("/*", i):
            j = s.find("*/", i + 2); i = n if j < 0 else j + 2; continue
        if c in "}]":
            k = len(out) - 1
            while k >= 0 and out[k] in " \t\r\n":
                k -= 1
            if k >= 0 and out[k] == ",":
                del out[k:]
        out.append(c); i += 1
    return json.loads("".join(out))

def line_with(data, needle):
    for n, ln in enumerate(lines_of(data), 1):
        if needle in ln:
            return n
    return 1

for rp in routes:
    path = os.path.join(root, rp)
    try:
        size = os.path.getsize(path)
        data = open(path, "rb").read(4 * 1024 * 1024)
    except OSError:
        continue
    base = os.path.basename(rp)
    if FONT.search(base):
        if size == 0:
            find(rp, 0, "an empty font file — a placeholder a task can overwrite", "0 bytes", data)
        elif data[:4] not in (b"wOF2", b"wOFF", b"\x00\x01\x00\x00", b"OTTO", b"true"):
            find(rp, 0, "not a font: no font magic bytes", short(data[:60].decode("utf-8", "replace")), data)
        continue
    if rp in DROPPERS:
        find(rp, 0, "a ChainDrop dropper file name", short(data[:80].decode("utf-8", "replace")), data)
        continue
    if base == "package.json":
        try:
            d = json.loads(data.decode("utf-8-sig", "replace"))
            scripts = d.get("scripts") or {}
        except Exception:
            scripts = {}
        for k, v in scripts.items():
            v = str(v)
            if k in ("preinstall", "install", "postinstall", "prepare", "prepublish") and BAD.search(v):
                find(rp, line_with(data, '"%s"' % k), "the %s hook runs: %s" % (k, short(v)[:60]), v, data)
                continue
            for t in re.findall(r"\bnode\s+(?:--[\w=-]+\s+)*([\w./-]+\.[cm]?js)\b", v):
                tp = os.path.join(os.path.dirname(path), t)
                try:
                    td = open(tp, "rb").read(4 * 1024 * 1024)
                except OSError:
                    continue
                longest = max((len(x) for x in td.split(b"\n")), default=0)
                why = ("one line of %d characters" % longest) if longest > 5000 else \
                      ("a hex-escaped _0x identifier array" if td.count(b"_0x") > 8 else
                       ("it assigns global[…]" if re.search(rb"global[ \t]*\[", td) else ""))
                if why:
                    find(rp, line_with(data, '"%s"' % k),
                         '"%s" runs %s first, and %s is obfuscated: %s' % (k, t, t, why), v, data)
        code_scan(rp, data)
        continue
    if rp.endswith(".vscode/tasks.json"):
        try:
            tasks = jsonc(data).get("tasks") or []
        except Exception:
            find(rp, 1, "cannot be parsed — VS Code is more tolerant than this check, read it by hand", "", data)
            continue
        for t in tasks if isinstance(tasks, list) else []:
            ro = t.get("runOptions") if isinstance(t, dict) else None
            if isinstance(ro, dict) and any(str(k).lower() == "runon" and str(v).lower() == "folderopen" for k, v in ro.items()):
                cmd = " ".join(str(x) for x in [t.get("command", "")] + list(t.get("args") or []))
                find(rp, line_with(data, str(t.get("label", "folderOpen"))),
                     'task "%s" runs when the folder is opened' % t.get("label", "?"), short(cmd)[:100], data)
        continue
    if AGENT.search(rp):
        try:
            d = jsonc(data)
        except Exception:
            find(rp, 1, "an agent config that cannot be parsed — read it by hand", "", data)
            continue
        def walk(o, ev=None):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k == "command" and isinstance(v, str) and BAD.search(v):
                        find(rp, line_with(data, v[:30]), "the %s hook runs a dropper" % (ev or "agent"), short(v)[:100], data)
                    else:
                        walk(v, k if isinstance(k, str) and k[:1].isupper() else ev)
            elif isinstance(o, list):
                for v in o:
                    walk(v, ev)
        walk(d.get("hooks") if isinstance(d, dict) else None)
        continue
    if rp.startswith(".husky/"):
        # Husky is ordinary tooling; what matters is what its hooks run.
        for n, ln in enumerate(lines_of(data), 1):
            if BAD.search(ln) and not ln.lstrip().startswith("#"):
                find(rp, n, "this git hook runs something that downloads or evaluates code", short(ln)[:100], data)
                break
        code_scan(rp, data)
        continue
    if base == ".gitignore":
        for n, ln in enumerate(lines_of(data), 1):
            if ln.strip().lstrip("/") in ("temp_auto_push.bat", "temp_interactive_push.bat", "branch_structure.json"):
                find(rp, n, "ignores a file the push-forging toolkit drops", ln.strip(), data)
        continue
    code_scan(rp, data)

# The source tree itself: campaign markers and code hidden past whitespace in
# any script, not only the routes — a payload imported by the app runs too.
# The routes-only first version dropped this, which the full scan had always
# done. Bounded: source files only, pruned as above, at most 6000 files and
# 64MB, and only ever adding findings.
seen_src, budget = set(routes), 64 * 1024 * 1024
for rp in srcfiles[:6000]:
    if rp in seen_src or budget <= 0:
        continue
    try:
        data = open(os.path.join(root, rp), "rb").read(2 * 1024 * 1024)
    except OSError:
        continue
    budget -= len(data)
    code_scan(rp, data, src=True)

# .git/hooks (and a configured core.hooksPath) run on commit, push, checkout.
# A hook someone planted is a route like any other; a sample is not.
hookdirs = [os.path.join(root, ".git", "hooks")]
hp = git("config", "core.hooksPath")
if hp and not hp.startswith(".husky"):
    hookdirs.append(hp if os.path.isabs(hp) else os.path.join(root, hp))
for hd in hookdirs:
    try:
        names = os.listdir(hd)
    except OSError:
        continue
    for h in names:
        hpth = os.path.join(hd, h)
        if h.endswith(".sample") or not os.path.isfile(hpth) or not os.access(hpth, os.X_OK):
            continue
        try:
            hdata = open(hpth, "rb").read(1024 * 1024)
        except OSError:
            continue
        rel = os.path.relpath(hpth, root)
        for n, ln in enumerate(lines_of(hdata), 1):
            if BAD.search(ln) and not ln.lstrip().startswith("#"):
                find(rel, n, "this git hook downloads or evaluates code", short(ln)[:100], hdata); break
        else:
            code_scan(rel, hdata)

for f in findings:
    print("\t".join([f[0], str(f[1]), f[2], f[3], f[4]]))
if findings:
    sys.exit(1)
if truncated:
    print("\t0\tthe repository is too large to walk within the gate's limits\t\t-")
    sys.exit(3)
try:
    os.makedirs(os.path.dirname(cachef), exist_ok=True)
    old = [l for l in open(cachef)][-200:] if os.path.exists(cachef) else []
    with open(cachef + ".tmp", "w") as fh:
        fh.writelines(l for l in old if not l.startswith(key + " "))
        fh.write("%s %d\n" % (key, int(time.time())))
    os.replace(cachef + ".tmp", cachef)
except OSError:
    pass
sys.exit(0)
PYROUTES
}

GATE_ALLOW="$SNARE_HOME/gate-allow"

# $1=dir  $2=nocache. 0 clean, 1 findings (formatted on stdout), 2 unverified.
_gate_tree(){
  local dir="$1" lit out rc
  [ -d "$dir" ] || return 0
  lit="$(mktemp "${SNARE_GATE_TMP:-${TMPDIR:-/tmp}}/snareioc.XXXXXX")" || return 2
  ioc_literals > "$lit"
  out="$(python3 -c "$(_gate_routes_py)" "$dir" "$lit" "$(ioc_regexes)" \
          "$GATE_CACHE" "$GATE_ALLOW" "$SNARE_VERSION" "${2:+1}" "$SNARE_ROOT" 2>&1)"; rc=$?
  rm -f "$lit"
  [ "$rc" = 0 ] && return 0
  if [ "$rc" = 1 ]; then
    local path line what ex
    while IFS="$(printf '\t')" read -r path line what ex _; do
      [ -z "$path" ] && continue
      if [ "${line:-0}" -gt 0 ] 2>/dev/null; then echo "  $path:$line — $what"
      else echo "  $path — $what"; fi
      [ -n "$ex" ] && echo "      ↳ $ex"
    done <<< "$out"
    return 1
  fi
  printf '%s\n' "$out" | cut -f3 | grep -v '^$' | head -3
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
  if ! GIT_TERMINAL_PROMPT=0 "${GATE_GIT[@]}" clone -q --depth 1 \
        ${sub[@]+"${sub[@]}"} ${3:+-b "$3"} -- "$url" "$q/repo" >"$q/err" 2>&1; then
    echo "could not fetch $2 to check it first:"; sed 's/^/    /' "$q/err" | tail -3
    rm -rf "$q"; return 2
  fi
  # Nothing checked out — the remote's HEAD names a branch that does not
  # exist, so the clone is "empty" even though branches are there. Scanning
  # that empty directory and calling it clean is a verdict about code nobody
  # looked at. Fetch every branch tip and scan each one instead; the next
  # `git checkout <branch>` is exactly what would bring it in.
  if ! "${GATE_GIT[@]}" -C "$q/repo" rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
    GIT_TERMINAL_PROMPT=0 "${GATE_GIT[@]}" -C "$q/repo" fetch --quiet --depth 1 origin \
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
    done < <("${GATE_GIT[@]}" -C "$q/repo" for-each-ref --format='%(refname)' refs/remotes/origin 2>/dev/null)
    rm -rf "$q"; return "$worst"
  fi
  _gate_tree "$q/repo" nocache; rc=$?
  rm -rf "$q"; return "$rc"
}

_gate_ref(){ # $1=dir $2=ref — scan a commit's tree without touching the working copy
  local sha q rc
  sha="$("${GATE_GIT[@]}" -C "$1" rev-parse --verify --quiet "$2^{commit}" 2>/dev/null)"
  if [ -z "$sha" ]; then
    # `git checkout feat` / `git switch feat` with only <remote>/feat present
    # creates the branch from the remote copy. That is new code arriving, and
    # "rev-parse failed" used to be read as "not a ref" and let through.
    local dwim
    dwim="$("${GATE_GIT[@]}" -C "$1" for-each-ref --format='%(refname)' "refs/remotes/*/$2" 2>/dev/null | head -1)"
    [ -n "$dwim" ] || return 0
    sha="$("${GATE_GIT[@]}" -C "$1" rev-parse --verify --quiet "$dwim^{commit}" 2>/dev/null)" || return 0
  fi
  [ "$sha" = "$("${GATE_GIT[@]}" -C "$1" rev-parse HEAD 2>/dev/null)" ] && return 0
  q="$(mktemp -d "${SNARE_GATE_TMP:-${TMPDIR:-/tmp}}/snaregate.XXXXXX")" || return 2
  if ! "${GATE_GIT[@]}" -C "$1" -c core.hooksPath=/dev/null worktree add --quiet --detach "$q/wt" "$sha" >/dev/null 2>&1; then
    rm -rf "$q"; echo "could not check out $2 to scan it"; return 2
  fi
  _gate_tree "$q/wt" nocache; rc=$?
  "${GATE_GIT[@]}" -C "$1" worktree remove --force "$q/wt" >/dev/null 2>&1
  rm -rf "$q"; "${GATE_GIT[@]}" -C "$1" worktree prune >/dev/null 2>&1
  return "$rc"
}

_gate_submodules(){ # $1=dir — each submodule at the commit the repo pins
  local dir="$1" path url sha q rc worst=0 res
  [ -f "$dir/.gitmodules" ] || return 0
  while IFS=' ' read -r key path; do
    [ -z "$path" ] && continue
    url="$("${GATE_GIT[@]}" -C "$dir" config -f .gitmodules --get "${key%.path}.url" 2>/dev/null)"
    sha="$("${GATE_GIT[@]}" -C "$dir" ls-tree HEAD -- "$path" 2>/dev/null | awk '{print $3}')"
    [ -n "$url" ] && [ -n "$sha" ] || continue
    case "$url" in ./*|../*) url="$("${GATE_GIT[@]}" -C "$dir" remote get-url origin 2>/dev/null)/$url" ;; esac
    q="$(mktemp -d "${SNARE_GATE_TMP:-${TMPDIR:-/tmp}}/snaregate.XXXXXX")" || return 2
    if git init -q "$q/s" && GIT_TERMINAL_PROMPT=0 "${GATE_GIT[@]}" -C "$q/s" \
         fetch -q --depth 1 -- "$url" "$sha" >/dev/null 2>&1 \
       && "${GATE_GIT[@]}" -C "$q/s" -c core.hooksPath=/dev/null checkout -q FETCH_HEAD >/dev/null 2>&1; then
      res="$(_gate_tree "$q/s" nocache)"; rc=$?
    else
      res="could not fetch submodule $path ($url) at $sha"; rc=2
    fi
    rm -rf "$q"
    if [ "$rc" != 0 ]; then
      printf '%s\n' "submodule $path:" "$res"
      if [ "$rc" = 1 ]; then worst=1; elif [ "$worst" = 0 ]; then worst=$rc; fi
    fi
  done < <("${GATE_GIT[@]}" -C "$dir" config -f .gitmodules --get-regexp '^submodule\..*\.path$' 2>/dev/null)
  return "$worst"
}

_gate_pull(){ # $1=dir  $2.. = remote [branch]
  local dir="$1" ref rc; shift
  "${GATE_GIT[@]}" -C "$dir" rev-parse --git-dir >/dev/null 2>&1 || return 0
  # Fetching runs nothing; it is merging the result into your tree that does.
  if [ $# -gt 0 ] && [ -n "$1" ]; then
    GIT_TERMINAL_PROMPT=0 "${GATE_GIT[@]}" -C "$dir" fetch --quiet "$@" 2>/dev/null \
      || { echo "could not fetch $* to check it first"; return 2; }
    ref=FETCH_HEAD
  else
    GIT_TERMINAL_PROMPT=0 "${GATE_GIT[@]}" -C "$dir" fetch --quiet 2>/dev/null \
      || { echo "could not fetch to check it first"; return 2; }
    ref="$("${GATE_GIT[@]}" -C "$dir" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null)"
    [ -n "$ref" ] || return 0
  fi
  _gate_ref "$dir" "$ref"; rc=$?
  [ "$rc" = 0 ] || return "$rc"
  # In place: this is where the forged-force-push check sees HEAD..@{u}.
  _gate_tree "$dir"
}

# ------------------------------------------------------------------- verdict
_gate_log(){ mkdir -p "$SNARE_LOGS" 2>/dev/null; echo "$(date '+%Y-%m-%dT%H:%M:%S') $*" >> "$GATE_LOG" 2>/dev/null; }

# What the gate stopped, for `snare respond` to pick up. The banner sends the
# person there ("let snare take charge"), so respond has to know WHAT was
# stopped — without this it ran a generic account sweep and never mentioned
# the repository that had just been blocked. One line per place:
#   local<TAB>/path/to/repo<TAB>command<TAB>/path/to/repo<TAB>
#   incoming<TAB>what<TAB>command<TAB>/path/to/repo<TAB>ref    a branch or pull
#   incoming<TAB>what<TAB>command<TAB><TAB>url                 a clone
# The last two fields are what `snare gate allow` needs to look again.
GATE_PENDING="$SNARE_LOGS/gate-pending"
_gate_pending_add(){ # $1=kind $2=where $3=command $4=dir $5=ref|url
  mkdir -p "$SNARE_LOGS" 2>/dev/null
  [ -f "$GATE_PENDING" ] && grep -qF "$(printf '%s\t%s\t' "$1" "$2")" "$GATE_PENDING" 2>/dev/null && return 0
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | tr '\n\t' '  ' | cut -c1-200)" \
    "${4:-}" "${5:-}" >> "$GATE_PENDING" 2>/dev/null
}

# $1 = command, $2 = cwd. Prints the verdict on stdout. 0 allow, 1 block.
_gate_decide(){
  local cmd="$1" cwd="$2" actions kind a b c d rc what seen_top="" out=() blocked=0 cant=0
  actions="$(python3 -c "$(_gate_py)" "$cmd" "$cwd" "$SNARE_ROOT" 2>/dev/null)" || {
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
              if ! "${GATE_GIT[@]}" -C "$a" rev-parse --git-dir >/dev/null 2>&1 && [ ! -f "$a/package.json" ]; then
                continue
              fi
              res="$(_gate_tree "$a")"; rc=$? ; what="$a" ;;
      clone)  res="$(_gate_clone "$a" "$b" "$c" "$d")"; rc=$? ; what="$b" ;;
      pull)   res="$(_gate_pull "$a" ${b:+"$b"} ${c:+"$c"})"; rc=$? ; what="incoming changes for $a" ;;
      ref)    res="$(_gate_ref "$a" "$b")"; rc=$? ; what="$b in $a" ;;
      unknown)
              # Something that may run repository code, by a route no list
              # can name. Scan the repository it runs in — once per repo.
              local top; top="$("${GATE_GIT[@]}" -C "$a" rev-parse --show-toplevel 2>/dev/null)"
              [ -n "$top" ] || continue          # not a repository: no committed payload
              case " $seen_top " in *" $top "*) continue ;; esac
              seen_top="$seen_top $top"
              res="$(_gate_tree "$top")"; rc=$?; what="$top" ;;
      submodules) res="$(_gate_submodules "$a")"; rc=$?; what="submodules of $a" ;;
      refuse) _gate_log "REFUSED agent tried: $b"
              out+=("refused: $b — approving a block or turning the gate off is the"
                    "    user's decision. Tell the user what was blocked; they run it"
                    "    in their own terminal.")
              cant=1; continue ;;
      unresolved) cant=1
              out+=("could not resolve a value in: $b"
                    "    (built at run time — \$(…), a backtick, or a variable set elsewhere)"
                    "    write the value out literally and the gate can check it"); continue ;;
      *) continue ;;
    esac
    case "$rc" in
      0) ;;
      1) blocked=1; out+=("$what carries a supply-chain payload:" "$res")
         case "$kind" in
           ref)   out+=("@allow snare gate allow $(printf '%q %q' "$a" "$b")") ;;
           clone) out+=("@allow snare gate allow $(printf '%q' "$b")") ;;
           pull)  out+=("@allow snare gate allow $(printf '%q' "$a")${c:+ $(printf '%q' "$b/$c")}") ;;
           *)     out+=("@allow snare gate allow $(printf '%q' "$what")") ;;
         esac
         case "$kind" in
           tree|unknown) local ptop; ptop="$("${GATE_GIT[@]}" -C "$what" rev-parse --show-toplevel 2>/dev/null)"
                         _gate_pending_add local "${ptop:-$what}" "$cmd" "${ptop:-$what}" ;;
           ref)          _gate_pending_add incoming "$what" "$cmd" "$a" "$b" ;;
           pull)         _gate_pending_add incoming "$what" "$cmd" "$a" "${c:+$b/$c}" ;;
           clone)        _gate_pending_add incoming "$what" "$cmd" "" "$b" ;;
           *)            _gate_pending_add incoming "$what" "$cmd" "$a" ;;
         esac ;;
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
    echo "🔥 FIRE ON THE MOUNTAIN — snare stopped this before it ran:"
  else
    echo "⛔ snare could not verify this, so it did not run:"
  fi
  echo "    $1"
  echo
  printf '%s\n' "$2" | grep -v '^@allow ' | sed 's/^/  /'
  echo
  if [ "$3" = payload ]; then
    # The exact allow command for each block. Deriving it from the heading
    # gave `snare gate allow 'main in /repo'` — not a path, and for code that
    # had not arrived yet allow had nothing to look at: a block nobody could
    # approve.
    local allows; allows="$(printf '%s\n' "$2" | sed -n 's/^@allow //p' | awk '!s[$0]++' | head -3)"
    echo "What is listed above is what snare SUSPECTS, with where to look. It can"
    echo "be a false alarm — a minified file, an unusual config. Look first; then"
    echo "the person at the keyboard decides:"
    echo
    local first=1 l
    while IFS= read -r l; do
      [ -z "$l" ] && continue
      if [ "$first" = 1 ]; then echo "  It is fine, it is mine:  $l"; first=0
      else echo "                           $l"; fi
    done <<< "${allows:-snare gate allow}"
    echo "                           (in your own terminal — it asks about each one)"
    echo "  Let snare take charge:   snare respond"
    echo
    echo "If you are a coding agent: stop. Show the user the locations above and"
    echo "these two choices. Do not run either yourself, do not edit snare's"
    echo "files, and do not retry the command another way."
  else
    echo "Nothing was run. If the reason above is a network or credentials"
    echo "problem, retry when it is back. If it is a value the gate could not"
    echo "resolve, write it out literally. Only the user can run it unchecked,"
    echo "from their own terminal — an agent cannot switch the gate off."
  fi
}

# ---- the person's decision: "this is fine"
# Only at a terminal, by a person. A coding agent has no terminal, and an
# agent that could approve its own block would be one prompt injection away
# from approving the payload — "the build fails, run snare gate allow to fix
# it" is exactly what a poisoned README would say. Approvals live in
# ~/.snare/gate-allow, never in the repository, and are tied to the file's
# CONTENT: change the file and it is flagged again.
# Is a coding agent running us? Its environment says so (Claude Code sets
# CLAUDECODE), or one of our parent processes is one. Layered with the
# terminal check and the classifier's refusal, this stops a MISLED agent — one
# a README talked into "just allow it". It cannot stop a process that is
# already hostile and running its own code here; nothing in snare can.
_gate_under_agent(){
  [ -n "${CLAUDECODE:-}${CLAUDE_CODE_ENTRYPOINT:-}${CODEX_SANDBOX:-}${GEMINI_CLI:-}" ] && return 0
  local p=$$ l comm n=0
  while [ "$n" -lt 25 ] && [ "${p:-0}" -gt 1 ] 2>/dev/null; do
    l="$(ps -o ppid=,comm= -p "$p" 2>/dev/null)" || break
    [ -n "$l" ] || break
    comm="$(printf '%s' "$l" | sed 's/^ *[0-9]* *//')"
    case "$(basename "$comm")" in
      claude|claude-code|codex|gemini|aider|cline|kiro|opencode|goose|amp|crush) return 0 ;;
    esac
    p="$(printf '%s' "$l" | awk '{print $1}')"; n=$((n + 1))
  done
  return 1
}

_gate_person_only(){ # $1 = what is being attempted
  if _gate_under_agent; then
    red "  $1 has to be done by a person, in their own terminal — not by a coding agent."
    dim "  An agent cannot approve its own block; that is the point of the gate."
    _gate_log "REFUSED $1 under an agent"
    return 1
  fi
  if [ ! -t 0 ] || [ ! -t 1 ]; then
    red "  $1 has to be run interactively, in a terminal."
    return 1
  fi
  return 0
}

# One approval: fingerprint, repository, path. Separate from the prompt so
# the record-and-honour logic is testable without a person.
_gate_allow_record(){ # $1=fingerprint $2=repo $3=path $4=what
  mkdir -p "$SNARE_HOME" 2>/dev/null
  echo "$1 $2 $3 $(date +%Y-%m-%d)" >> "$GATE_ALLOW"
  _gate_log "ALLOW $2 $3 $4"
}

# What `snare gate allow` can approve for a target: the working copy, and the
# code a block stopped before it arrived — a branch, the upstream a pull would
# merge, or a repository a clone would fetch. Without the incoming half, a
# false alarm on a pull or a checkout could not be approved anywhere: allow
# looked only at the files on disk, found them clean, and the gate kept
# blocking. Prints TSV (label path line what excerpt fingerprint), first
# finding per fingerprint only. Needs no person, so it is testable; the
# approving is _gate_allow's.
#   $1 = a directory (default .) or a clone URL   $2 = a ref (optional)
_gate_allow_scan(){
  local target="${1:-$PWD}" ref="${2:-}" q lit dir="" top head r sha n=0
  q="$(mktemp -d "${TMPDIR:-/tmp}/snareallow.XXXXXX")" || return 2
  lit="$q/lit"; ioc_literals > "$lit"
  local trees=() labels=() refs=()
  if [ -d "$target" ]; then
    dir="$(cd "$target" && pwd -P)"
    top="$("${GATE_GIT[@]}" -C "$dir" rev-parse --show-toplevel 2>/dev/null)"; [ -n "$top" ] && dir="$top"
    trees+=("$dir"); labels+=("working copy")
    if [ -n "$ref" ]; then refs+=("$ref")
    else
      r="$("${GATE_GIT[@]}" -C "$dir" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null)"
      [ -n "$r" ] && refs+=("$r")
      if [ -s "$GATE_PENDING" ]; then
        local k pd pr
        while IFS="$(printf '\t')" read -r k _ _ pd pr; do
          [ "$k" = incoming ] && [ "$pd" = "$dir" ] && [ -n "$pr" ] && refs+=("$pr")
        done < "$GATE_PENDING"
      fi
    fi
    head="$("${GATE_GIT[@]}" -C "$dir" rev-parse HEAD 2>/dev/null)"
    local seen=" "
    for r in ${refs[@]+"${refs[@]}"}; do
      sha="$("${GATE_GIT[@]}" -C "$dir" rev-parse --verify --quiet "$r^{commit}" 2>/dev/null)"
      if [ -z "$sha" ]; then   # `main` with only origin/main present, as checkout would DWIM
        local dw; dw="$("${GATE_GIT[@]}" -C "$dir" for-each-ref --format='%(refname)' "refs/remotes/*/$r" 2>/dev/null | head -1)"
        [ -n "$dw" ] && sha="$("${GATE_GIT[@]}" -C "$dir" rev-parse --verify --quiet "$dw^{commit}" 2>/dev/null)"
      fi
      [ -n "$sha" ] && [ "$sha" != "$head" ] || continue
      case "$seen" in *" $sha "*) continue ;; esac; seen="$seen$sha "
      n=$((n + 1))
      "${GATE_GIT[@]}" -C "$dir" worktree add --quiet --detach "$q/wt$n" "$sha" >/dev/null 2>&1 || continue
      trees+=("$q/wt$n"); labels+=("$r")
    done
  else
    case "$target" in
      *://*|*@*:*) GIT_TERMINAL_PROMPT=0 "${GATE_GIT[@]}" clone -q --depth 1 ${ref:+-b "$ref"} -- "$target" "$q/clone" >/dev/null 2>&1 \
                     || { echo "could not fetch $target"; rm -rf "$q"; return 2; }
                   trees+=("$q/clone"); labels+=("$target") ;;
      *) echo "no such directory: $target"; rm -rf "$q"; return 2 ;;
    esac
  fi
  local i out fps=" " any=0 path line what ex fp
  for i in "${!trees[@]}"; do
    out="$(python3 -c "$(_gate_routes_py)" "${trees[$i]}" "$lit" "$(ioc_regexes)" /dev/null /dev/null "$SNARE_VERSION" 1 "$SNARE_ROOT" 2>/dev/null)"
    while IFS="$(printf '\t')" read -r path line what ex fp; do
      [ -z "$path" ] || [ -z "$fp" ] || [ "$fp" = "-" ] && continue
      case "$fps" in *" $fp "*) continue ;; esac; fps="$fps$fp "
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${labels[$i]}" "$path" "$line" "$what" "$ex" "$fp"; any=1
    done <<< "$out"
  done
  [ -n "$dir" ] && for i in $(seq 1 "$n"); do "${GATE_GIT[@]}" -C "$dir" worktree remove --force "$q/wt$i" >/dev/null 2>&1; done
  [ -n "$dir" ] && "${GATE_GIT[@]}" -C "$dir" worktree prune >/dev/null 2>&1
  rm -rf "$q"
  [ "$any" = 1 ] && return 1
  return 0
}

_gate_allow(){ # $1 = dir or clone URL, $2 = ref (optional)
  local target="${1:-$PWD}" ref="${2:-}" out rc label path line what ex fp ans n=0 added=0 where
  _gate_person_only "snare gate allow" || return 1
  if [ -d "$target" ]; then
    where="$(cd "$target" && pwd -P)"
    local top; top="$("${GATE_GIT[@]}" -C "$where" rev-parse --show-toplevel 2>/dev/null)"; [ -n "$top" ] && where="$top"
  else where="$target"; fi
  out="$(_gate_allow_scan "$target" "$ref")"; rc=$?
  if [ "$rc" = 0 ]; then grn "  nothing to allow — $where is clean, and so is what it would bring in"; return 0; fi
  if [ "$rc" = 2 ]; then red "  $out"; return 1; fi
  hdr "snare gate allow — $where"
  dim "  Each is something snare suspects. Allow only what you have looked at and"
  dim "  recognise as your own. The approval is tied to the file's current content."
  mkdir -p "$SNARE_HOME" 2>/dev/null
  while IFS="$(printf '\t')" read -r label path line what ex fp <&3; do
    [ -z "$fp" ] && continue
    n=$((n + 1)); echo
    if [ "${line:-0}" -gt 0 ] 2>/dev/null; then echo "  $n. $path:$line — $what"; else echo "  $n. $path — $what"; fi
    [ "$label" = "working copy" ] || dim "       (in $label — not on disk yet; this is what would arrive)"
    [ -n "$ex" ] && echo "       ↳ $ex"
    printf '     Allow this one? [y/N] '; IFS= read -r ans
    case "$ans" in
      y|Y|yes) _gate_allow_record "$fp" "$where" "$path" "$what"; added=$((added + 1)) ;;
      *) echo "     left blocked" ;;
    esac
  done 3<<< "$out"
  echo
  [ "$added" -gt 0 ] && grn "  allowed $added — the gate lets it through unless something new appears"
  dim "  Review or undo:  snare gate allowed  |  snare gate forget '$where'"
}

_gate_allowed(){
  [ -s "$GATE_ALLOW" ] || { dim "  nothing allowed"; return 0; }
  hdr "allowed by you"
  awk '{ printf "  %s  %s  %s\n", $4, $2, $3 }' "$GATE_ALLOW"
}

_gate_forget(){ # $1 = dir, or "all"
  [ -f "$GATE_ALLOW" ] || return 0
  _gate_person_only "snare gate forget" || return 1
  if [ "${1:-}" = all ]; then : > "$GATE_ALLOW"; grn "  all approvals removed"; return 0; fi
  local dir; dir="$(cd "${1:-$PWD}" 2>/dev/null && pwd -P)" || die "no such directory"
  local top; top="$("${GATE_GIT[@]}" -C "$dir" rev-parse --show-toplevel 2>/dev/null)"; [ -n "$top" ] && dir="$top"
  awk -v d="$dir" '$2 != d' "$GATE_ALLOW" > "$GATE_ALLOW.tmp" && mv "$GATE_ALLOW.tmp" "$GATE_ALLOW"
  grn "  approvals for $dir removed — it will be checked from scratch"
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
  # (An agent that tries to approve a block or disable the gate is refused by
  # the classifier's "refuse" action, which looks at the commands the shell
  # would run — not at raw text, which also matched docs and heredoc data.)
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
        [ -n "$verdict" ] && printf '%s\n' "$verdict" | grep -v '^@allow '
        grn "  clean — safe to run: $cmd"; return 0
      fi
      printf '%s\n' "$verdict" | grep -q 'supply-chain payload' && kind=payload || kind=unverified
      [ "$kind" = payload ] && snare_desktop_notify "FIRE ON THE MOUNTAIN: snare blocked $cmd"
      _gate_banner "$cmd" "$verdict" "$kind" >&2
      return 1 ;;
    allow)   shift; _gate_allow "$@" ;;
    allowed) _gate_allowed ;;
    forget)  shift; _gate_forget "$@" ;;
    ""|-h|--help)
      echo "usage: snare gate -- <command>    check before running it (0 = clean)"
      echo "       snare gate allow [dir [branch]|url]  you looked, it is fine: allow what is flagged, on disk or incoming"
      echo "       snare gate allowed         what you have allowed"
      echo "       snare gate forget [dir|all] withdraw approvals"
      echo "       snare gate --hook          Claude Code PreToolUse hook (stdin JSON)" ;;
    *) cmd_gate -- "$@" ;;
  esac
}
