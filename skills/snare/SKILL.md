---
name: snare
description: Scan a Git repository for supply-chain malware committed into the repo itself — droppers hidden in .vscode/tasks.json behind runOn:folderOpen, or appended after thousands of spaces in a build config like postcss.config.js, executing a payload disguised as a .woff2 font. npm audit, the lockfile and Dependabot are all clean on these because there is no malicious dependency. Use before opening an unfamiliar repository in an editor, before the first build or dev server on a fresh clone, when onboarding a project, when a dependency or repo is suspected of compromise, or when the user mentions shai-hulud, a committed dropper, EtherHiding, or a clipboard stealer.
---

# snare

A supply-chain attack `npm audit` cannot see, and the scanner that finds it.

**No `npm install` required.** The dropper is committed directly into the
repository, so there is no malicious dependency, nothing in the lockfile, and
nothing for Dependabot to report. One sample sat in a repo for five months.

Field guide: <https://avioflagos.github.io/snare/>

## When to reach for this

- **A fresh clone, before the first build or before opening it in an editor.**
  This is the highest-value moment, because those are the two triggers.
- Onboarding or auditing a project you did not write.
- A dependency, contributor or repo is suspected of compromise.
- The user mentions shai-hulud, a committed dropper, EtherHiding, or a
  clipboard stealer.

## What it catches

Two execution routes, neither needing `npm install`:

| Where | Trigger |
| --- | --- |
| `.vscode/tasks.json` with `"runOn": "folderOpen"` | **Opening the folder in an editor** |
| A build config (`postcss.config.js`, …) | `next dev` / `next build` |

Both hide the same way: the payload is appended after **thousands of spaces** on
one line, so the file looks normal in an editor. The executed file is often
disguised as an asset — a `public/fonts/*.woff2` that is really JavaScript. A
genuine `.woff2` starts with the magic bytes `wOF2`; snare checks.

Blocking the C2 address does not work: this family resolves its
command-and-control IP *from the Ethereum blockchain*, and the operator rotates
it by sending one transaction.

## Commands

Requires `bash`, `git`, `python3` and `gh`. `snare doctor` verifies the setup.

### Safe to run unprompted — read-only

```bash
snare doctor                   # is snare itself installed and authenticated
snare scan repo .              # this clone: tree, every branch, full history
snare scan github              # every repo you can reach, via API, no cloning
snare scan github --all-branches
snare guard status             # is the background guard running
snare guard log                # what it has killed
```

Scanning reads. Run it and report what it finds.

### Never run without explicit human confirmation

These change repositories, history, or contact other people. Present what the
command would do, name the blast radius, and wait for a clear yes.

| Command | Why it is gated |
| --- | --- |
| `snare fix owner/repo --push` | Rewrites branch tips on a **remote** repository |
| `snare fix owner/repo --purge-history --push` | **Rewrites published history.** Every collaborator's clone diverges and must be re-cloned or reset. Irreversible from their side |
| `snare notify owner/repo --issue --mail` | Files a **public GitHub issue** @-mentioning collaborators and opens mail drafts. Outward-facing, under the user's name |
| `snare guard install` | Installs a background agent that polls once a second and kills processes |

`snare fix` without `--push` is a dry run and is safe to show.

`notify` **never sends** anything — it opens pre-filled drafts the human
reviews and sends from their own account, which is what makes the warning
credible. Do not attempt to send on their behalf.

## Reading a result

**A finding is an incident, not a lint error.** If `scan` reports something:

1. **Stop.** Do not run a build, start a dev server, or open the folder in an
   editor — those are the triggers.
2. Report exactly what was found and where, verbatim.
3. Ask before any `fix`. History rewriting is the user's decision to make,
   and it affects every collaborator, not just them.
4. If the repo has other contributors, raise `notify` as the next step —
   warning people is part of the fix, not an optional extra.

**A clean result is not a guarantee.** snare catches this family. It is not a
general-purpose malware scanner, and a clean report is not permission to trust
an unknown repository.

## The guard, honestly

`snare guard` polls once a second and kills matching **interpreter** processes
plus anything holding a socket to a known C2. Restricting kills to interpreters
is deliberate — a shell or editor that merely *mentions* an IOC string must
never be killed.

It is a safety net, not a guarantee: a payload can act before the next poll, it
cannot see code already running inside another process, and it will miss
variants on different infrastructure. **Removing the malware from the repo is
the actual fix.** Never treat a running guard as permission to open an untrusted
repository.

## Auth

snare uses the user's own GitHub credentials and stores nothing. Scopes needed
are `repo` and `workflow`; do not suggest a token with broader permissions.
If `gh` is not authenticated, say so — do not attempt to authenticate as them.
