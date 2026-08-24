# snare

Find, kill and clean up supply-chain malware that hides in your repositories.

Built while cleaning up a live infection: a dropper committed into four
repositories across four GitHub organisations, which re-infected a freshly
reinstalled machine on the next `git clone`.

## What it catches

**Two execution routes, neither of which needs `npm install`:**

| Where | Trigger |
|---|---|
| `.vscode/tasks.json` with `"runOn": "folderOpen"` | **Opening the folder in VS Code** |
| A build config (`postcss.config.js`, etc.) | `next dev` / `next build` |

Both hide the same way: the payload is appended after **thousands of spaces**
on one line, so the file looks perfectly normal in an editor. The executed file
is often disguised as an asset — a `public/fonts/*.woff2` that is really
JavaScript. (A genuine `.woff2` starts with the magic bytes `wOF2`; snare
checks.)

**Why blocking the C2 IP does not work:** this family resolves its
command-and-control address *from the Ethereum blockchain* — reading
transactions from a known address via Blockscout and decoding an IPv4 address
out of them. The operator rotates the IP by sending one transaction.

## Install

```bash
git clone <this-repo> ~/snare && cd ~/snare && ./install.sh
gh auth login          # your own account — snare ships no token
snare doctor
```

Requires `bash`, `git`, `python3`, `gh`. `git-filter-repo` only for `--purge-history`.

## Use

```bash
# TRACK — kill the loader on sight (~1s), from login onwards
snare guard install
snare guard status
snare guard log

# FIND
snare scan repo .              # one clone: tree, every branch, full history
snare scan github              # every repo you can reach, via API, no cloning
snare scan github --all-branches

# FIX  (always backs up to ~/.snare/backups first)
snare fix owner/repo                            # dry run
snare fix owner/repo --push                     # clean branch tips
snare fix owner/repo --purge-history --push     # erase from all history

# INFORM
snare notify owner/repo --issue --mail
```

`notify` files a GitHub issue @-mentioning collaborators (this reaches people
who publish no email address) and opens a **pre-filled mail draft per person**
in your mail client. **It never sends anything** — you review and send from
your own account, which is also what makes the warning credible.

## Auth

snare uses **your** GitHub credentials and stores nothing:

```bash
gh auth login              # browser, or paste your own token
export GH_TOKEN=...        # or an env var
```

Scopes needed: `repo`, `workflow`. Do not use a token with broader permissions.

## The guard, honestly

It polls once a second and kills matching **interpreter** processes (`node`,
`osascript`, `bun`, `deno`, `python`, …) plus anything holding a socket to a
known C2. Restricting kills to interpreters is deliberate: a shell or editor
that merely *mentions* an IOC string must never be killed.

It is a safety net, not a guarantee. A payload can act before the next poll,
it cannot see code already running inside another process, and it will miss
variants using different infrastructure. **Removing the malware from the repo
is the actual fix** — never treat a running guard as permission to open an
untrusted repository.

## Extending

All detection reads `iocs.txt` (one extended-regex per line, `#` for comments).
Add a pattern there and every command picks it up.

State lives in `$SNARE_HOME` (default `~/.snare`): `logs/`, `logs/evidence/`,
`backups/`, `work/`.

## Limits

- `scan github` sees **branch tips only** — a payload committed then deleted
  survives in history. Use `snare scan repo` on a clone for that.
- Rewriting history does not remove **forks**, **PR refs**, or old objects
  still reachable by SHA. Ask GitHub Support to garbage-collect.
- macOS-focused (the guard uses `launchd` and `osascript`). Scanning and
  fixing work anywhere bash does.
