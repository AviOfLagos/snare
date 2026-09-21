# Changelog

Versions follow [semantic versioning](https://semver.org). Anything that made
snare report **clean on an infected repository** is listed first in its release,
because that is the failure that matters most in a scanner.

`snare version` shows your version and commit. `snare update --check` compares
commits, not just version numbers.

## [Unreleased]

### Fixed — remediation

- **`fix` deleted the files a project needs instead of cleaning them.** The
  branch-tip pass removed every file matching an IOC string — and a payload
  appended to `postcss.config.mjs` *is* an IOC string, so the build config was
  deleted before the strip pass further down the same function could ever see
  it. `snare fix --all --push` pushed a commit that removed the malware and the
  project's build along with it. Stripping now runs first: a file the project
  needs (any `*.config.*`, `package.json`, a lockfile, `tsconfig*.json`) is
  stripped and kept, never deleted, and only files that are payload and nothing
  else are removed.
- **`.vscode/tasks.json` was deleted whole.** A repository with a real build
  task and one injected `folderOpen` task lost both. Only the `folderOpen` task
  is removed now; the file goes only when nothing legitimate is left in it, and
  a file that merely mentions `folderOpen` without defining such a task is
  reported rather than deleted.
- **A payload on a line of its own was never removed.** Both cleaners keyed on
  the one-line signature — code, a long whitespace run, then code. The same
  payload placed after a newline matched neither, so `--purge-history` rewrote
  nothing and still reported success. Dropping a whole line is destructive, so
  that rule is gated narrowly: long, minified-shaped, a hard campaign marker
  *and* obfuscated code. Gating on the marker alone deleted every line that
  legitimately quotes one, including the guard's own kill pattern.
- **Tip cleaning looked for artifacts by content only.** `setup_bun.js` and a
  payload wearing a `.woff2` extension are identified by filename and by magic
  bytes, which no content grep can see — so `scan` reported them and `fix`
  walked straight past them.
- **`--purge-history` verified itself by grepping for one marker string.** An
  obfuscated variant contains none of them, so the check passed on blobs it had
  not changed. It now re-runs the same cleaner over every blob and counts what
  is still strippable, so the verification and the fix cannot disagree.
- **The two cleaners had drifted apart.** Tip cleaning and history purging each
  carried their own copy of what a payload looks like. There is one definition
  now, shared by both.
- **A dry run that found something was reported as a failure.** `snare fix --all`
  over five infected repositories printed `succeeded: 0    failed: 5`, and `FAILED:`
  against each one, when it had read all five correctly and — being a dry run —
  deliberately changed nothing. A dry run with findings now returns 3 instead of
  sharing an exit code with a genuine error, and the summary reads
  `carrying a payload: 5    already clean: 0    unreadable: 0`.
- `fix` honours `.snare-tool` the way `scan` and `hook` already did. Without it,
  remediating a fork of snare stripped the guard's own kill pattern out of
  `lib/guard.sh`.

### Fixed — `snare doctor` was macOS-only, and said so in neither place

Reported by a Linux user whose guard was running while doctor said it was not.

- **The guard check asked `launchctl` on every platform.** On Linux the guard is
  a systemd user unit and on Windows a scheduled task, so doctor reported "guard
  not installed" no matter what it was actually doing. It now asks the right
  supervisor per platform, distinguishes *installed but stopped* from *not
  installed*, and counts a hand-started `snare guard run` as running.
- **"Persistence spots" checked three macOS paths that do not exist on Linux**,
  found nothing in them, and printed `empty` three times — a clean bill of
  health from having looked nowhere. This is the same false-clean shape as the
  scanner bugs in 1.1.0, in the one command whose entire job is answering "is
  this machine compromised". It now checks the locations that platform actually
  uses — systemd user units, autostart, `/etc/cron.d` — and lists what it finds
  rather than only counting. The user crontab is checked everywhere, which is
  where the RAT on the reference host lived.
- **Added a Node and npm integrity check**, because the package manager is a
  file like any other and nothing was looking at it. It finds every npm on the
  system without *running* npm to ask — running npm was the thing that executed
  the loader — and flags `lib/*.js` carrying a hidden payload or a known IOC. It
  also reports `~/.node_modules` (a legacy global resolution path, rarely
  deliberate, and where the RAT's dependencies were planted) and a `NODE_OPTIONS`
  `--require`/`--import` injection in the environment or a shell profile.
- `cmd_doctor` moved out of `bin/snare` into `lib/doctor.sh`, like every other
  command.
- `snare selftest` covers all of it: 3 checks asserting a patched npm is flagged,
  an intact one is not, and `guard_state` answers for the host platform. 27 in
  total.

### Added — where a detection came from

Written after a live infection on a development machine where the guard was
killing the loader every few minutes and the log said only "a node process
matched an IOC". Finding the actual source — npm's own `lib/cli.js`, with 1.4MB
appended after 200 spaces, so every `npm` invocation ran the loader — took an
hour of manual work that the guard had all the information to do itself.

- **`snare guard origins`** — an append-only provenance log
  (`$SNARE_HOME/logs/origins.log`) recording, per detection: the file
  responsible, the working directory, the full parent chain, and a link to the
  evidence dump. It ends with the most frequent origins, because a source that
  keeps re-launching shows up as a count.
- The guard now walks the **parent chain** at detection time and records it.
  `node -e <payload>` names no file on disk; its parent almost always does, and
  that parent is the thing that needs cleaning. On the host above this resolves
  in one line to `.../node_modules/npm/lib/cli.js`.
- Ancestry is captured **before** anything else in the handler. These processes
  exit in well under a second, and a parent that has already gone is a dead end.
- A dropper that deletes itself is still reported, as
  `<path> (no longer on disk)`. Reporting a path that is gone beats reporting
  nothing, which is what the first version did.
- Evidence dumps gain an `origin` section and the parent chain. They do **not**
  record the process environment: on a machine being investigated for credential
  theft, writing every environment variable into a log file is its own leak.

### Added — IOCs from a live host, 2026-09-06..08

Campaign `A8-4893-2`, two stages with two unrelated C2 addresses:

- `193.247.144.38` — the EtherHiding loader's C2. Not the address in the
  existing IOC list; the operator rotates it from the blockchain, which is the
  whole point of that design and the reason blocking one IP is not a fix.
- `194.11.226.41` — a **second, separate implant**: an obfuscated socket.io RAT
  dropped to `~/.local/share/<random>.js`, held by a `crontab @reboot` line,
  writing to a decoy `VSCodeUpdater.log`, with its dependencies (`axios`,
  `socket.io-client`) installed into `~/.node_modules` so Node's legacy global
  resolution would find them. Its command line contained **no loader string at
  all** — the guard would not have caught it. It is matched now by the shape of
  its argument: `--token "http://IP:PORT|SECRET"`.
- `/*RS260605*/`, `/*M260630A*/` — markers the payload writes into what it
  patches, and the ones that identify a patched file at rest.
- The npm-patch route matters on its own: `ignore-scripts=true` was set on that
  host and did not help, because the package manager itself was modified rather
  than any package's install script.

### Added — one command from picking to fixing

- **`snare fix --pick`** chooses organisations from the same list `scan orgs`
  prints, scans them, and remediates what it finds, in one pass. It is a dry run
  unless you add `--push`; `--purge-history --push` also erases the payload from
  all history. `--owner a,b` is the same thing without the prompt, for a script
  or a timer. The destructive flags stay on the command line rather than hiding
  inside a friendlier-sounding verb — force-pushing rewritten history across an
  organisation should be legible in your shell history.
- With `--purge-history` it checks for `git-filter-repo` **before** the picker
  and the scan. The check previously lived inside the per-repository purge, so
  you chose an organisation, waited out a full scan and a clone, and only then
  found out it could not proceed.
- It repeats the rotate-first warning at the last point before anything is
  written to a repository other people depend on.

### Added — choosing what to scan

- **`snare scan orgs`** lists every account and organisation your token can
  reach, largest first, with how many repositories each holds and how many of
  those are private. Until now the only way to narrow a scan was to already know
  an organisation's exact login; the only alternative was scanning everything,
  which on a real account is 22 organisations and around 950 repositories —
  several thousand API calls. Individual accounts you hold a single collaborator
  bit on are collapsed into a count; `--all` lists them.
- **`snare scan github --pick`** shows that same list and lets you choose from
  it — `2`, `2,5`, `1-4`, `2,7-9` or `all`. It refuses to run without a
  terminal and tells you the non-interactive equivalent instead.
- **`snare scan github --owner` takes a list**: `--owner a,b,c`. This is what
  `--pick` resolves to, so a selection made once can be re-run from a script or
  a timer.
- The repository counts are the number `--owner` will *actually* scan, taken
  from the same call the scan uses. Deriving them from the affiliation endpoint
  was cheaper but wrong — it counts only repositories you are directly attached
  to, so one organisation listed as holding 1 repository actually held 5, and
  another listed as 4 held 123. Counting runs in bounded parallel batches
  (`SNARE_COUNT_JOBS`, default 8); sequentially it took 41 seconds.

### Fixed — scanning

- **An unrecognised flag to `scan github` was ignored in silence.** `--all-branch`
  instead of `--all-branches`, or any other typo, quietly scanned every
  repository you can reach rather than the narrower thing you asked for. Unknown
  flags are now an error, as they already were in `report` and `respond`.
- **The local `scan repo` lost its primary detector on Debian and Ubuntu.**
  The structural test — code, a long whitespace run, then more code, the signal
  that catches a variant carrying none of the IOC strings — was an `awk`
  interval expression, `{50,}`. `mawk`, the default `awk` on Debian and Ubuntu,
  accepts that syntax and matches nothing, so the test never fired there: a
  repository whose only infection was a payload padded past a run of whitespace
  came back `No IOC matches`, exit 0. It reported clean on an infected
  repository, which is the failure this changelog lists first. The test now
  runs through `grep -E`, the same engine `scan github`, `fix` and `hook`
  already use for that pattern, and the `selftest` sample it is checked against
  no longer carries an IOC string of its own — it did, so the test passed
  through the working-tree IOC grep and never exercised the structural test at
  all.
- **The by-hand long-line command on the inspection page never looked at the
  file types the payload lands in.** It globbed `*.js`, so `postcss.config.mjs`
  and `tailwind.config.mjs` — the file every live infection of this campaign
  sits in — were not passed to `awk` at all. It now also matches `*.mjs` and
  `*.cjs`, the same set `scan repo` walks.

### Added — test coverage

- `snare selftest` now covers remediation, not just detection: 14 checks
  asserting that a build config and `package.json` survive with the payload gone
  and still parse, that a dropper, a fake font and a worm artifact are removed,
  and that a genuine font, a clean source file and an honest build task are left
  alone. 24 checks in total.

## [1.2.0] — 2026-09-10

Remediation could delete the file it was meant to clean. If you ran
`snare fix --push` on a release before this one, check the repository: a build
config may have been removed rather than repaired.

### Fixed — destructive behaviour

- **`fix` deleted the build config instead of cleaning it.** The delete pass
  removed any file matching an IOC string, and a payload appended to
  `postcss.config.mjs` *is* an IOC string — so the file was gone before the
  strip pass further down the same function could reach it. It pushed a commit
  that removed the malware and the project's build with it. Stripping runs
  first now, and a file the project needs is cleaned and kept, never deleted.
  Reported and fixed by @phoenixdahdev. (#39)
- **`.vscode/tasks.json` was deleted whole**, losing honest build tasks along
  with the injected `folderOpen` one. Only the malicious task goes now. (#39)
- **A payload on a line of its own was never removed.** Both cleaners keyed on
  the one-line signature. The new rule is gated narrowly — long, minified in
  shape, a hard campaign marker *and* obfuscated code — because dropping a
  whole line on a weaker signal is itself destructive. (#39)

### Fixed — detection and coverage

- **Worm artifacts and fake assets are now found by filename and magic bytes**
  during remediation, not only during scanning: `scan` reported them and `fix`
  walked straight past. (#39)
- **npm's own `lib/cli.js` is checked.** A live host was found with ~1.4MB
  appended to it after 200 spaces, so every `npm` invocation ran the loader —
  `--ignore-scripts` does not help, because it is the package manager itself
  and not a package script. New campaign `A8-4893-2`, with two C2 addresses and
  a socket.io RAT held by a crontab `@reboot` line. (#39)
- The doctor fixture path is normalised, so the npm check no longer failed on
  macOS while passing on Linux — the suite reported "detection is broken" for a
  detector that was working correctly. (#39)

### Fixed — contribution and platform

- **No pull request from a fork could ever pass CI.** `ci.yml` passed
  `github.head_ref` to the reusable workflow, which then tried to check that
  ref out of this repository — a fork's branch does not exist here, so checkout
  failed three times before a single check ran. The first outside contribution
  hit it, and the failure looked like the contributor's fault rather than ours.
  It uses `refs/pull/N/head` now. (#40)
- **Windows `guard install` failed with no explanation.** `schtasks.exe` needs
  a Windows path and was handed an MSYS one, and every error was discarded. It
  now converts the path, prints the real error, and falls back to a Startup
  entry that needs no administrator rights. (#32)
- snare flagged its own plugin manifest and skill, which quote the malware's
  keywords because they describe it. (#38)

### Added

- **`snare respond`** — one guided clean-up instead of nine commands, in the
  order that actually works: rotate credentials, clean the machine you push
  from, then the repositories, then tell your collaborators. Resumable, asks
  before every action, refuses to run unattended. (#33, #34)
- **A passive update notice.** Every command now says, at most once a day and
  in one line, when the installation is behind. It never blocks — the check is
  cached and refreshed off the command path — sends nothing, and is off with
  `SNARE_NO_UPDATE_CHECK=1`. The people who most need the fixes are the ones
  who cloned once and never thought about it again. (#41)
- **snare ships as a Claude Code plugin**, so a coding agent can find and run
  it. (#38)
- An incident-response walkthrough on the site, and a copy-paste prompt for
  people who would rather have an AI assistant do the work — written to forbid
  the assistant from running anything destructive without asking. (#36)

### Changed

- Post-scan guidance leads with rotating credentials and cleaning your machine,
  not with `snare fix`. Cleaning repositories first is wasted work while the
  machine that pushes to them is still infected. (#31)
- The notify templates lead with rotation too, and carry the full list
  including the clipboard and the Actions workflow that keeps exfiltrating
  after the dropper is gone. (#32)
- `snare version` no longer runs a live fetch to decide whether to nudge; a
  one-line command took about five seconds on a slow link. (#41)
- The site is a multi-page field guide with corrected document semantics, a
  crawler policy naming 29 search and AI crawlers, `llms.txt`, and structured
  data on every page. (#33, #35, #37)

## [1.1.0] — 2026-08-29

Everything since the initial release. If you installed snare before this,
**update before you trust a clean result** — several defects below made the
scanner report clean on genuinely infected repositories.

### Fixed — false clean results

- **The working-tree scan never ran.** `"${EXCL[@]}"` on an empty array is fatal
  under `set -u` on bash 3.2, which is what macOS ships. The substitution died,
  the output came back empty, and the `else` branch printed `clean`. Only
  snare's own repository populated that array, so it was the only repository
  section 1 ever actually scanned. (#2, #3)
- **The API scan never looked at build configs.** `postcss.config.*` and
  `next.config.*` were never fetched and the hidden-payload heuristic was never
  applied, so one of the two execution routes documented in the README could not
  be detected over the API. A real infection survived a clean 127-repository
  sweep this way. (#2, #3)
- **The heuristic keyed on raw line length.** `length > 1500` missed a 664-char
  payload. The structural signature — code, a run of 50+ whitespace, then more
  code — is now the primary test and catches a payload of any length. (#2, #3)
- **`fix --purge-history` could force-push while removing nothing.** The blob
  callback only rewrote blobs containing a hardcoded marker, and the
  completeness check grepped for one of those same markers. On an obfuscated
  variant it stripped nothing, verified nothing, reported success, and pushed.
  (#2, #3)
- **Missing `xxd` made every genuine font look like a payload.** `xxd` ships
  with vim and is absent from minimal Linux images and some Git Bash installs.
  When it was missing the magic-byte read returned empty and fell through to the
  failure case — and in the pre-push hook that blocked every push from any
  repository containing fonts. Now uses POSIX `od`, and an unreadable magic
  counts as *cannot tell* rather than an accusation. (#29)

### Fixed — evasion and detection

- **The guard could be evaded by putting `snare` in a process argv.** It skipped
  any process whose command line contained the substring `snare` anywhere, so a
  payload hid from it by being named `node /tmp/snare-helper.js`. Matching is now
  against the real install path. (#17)
- **Every legitimate `.ttf` was flagged.** The TrueType magic case compared
  against `$'\x00\x01\x00\x00'`, but bash cannot hold NUL bytes, so that branch
  could never match. (#2, #3)
- **Long minified files were reported as findings.** Raw line length is now an
  informational note, not a finding — a scanner nobody reads protects nobody.
  (#10)
- Actions workflow persistence is now detected by content (whole-secret-context
  dumps, known exfiltration endpoints), not just by filename. (#22, #23)

### Fixed — platform and upgrade

- **Install was broken on Windows Git Bash.** The installer fell back to copying
  when `ln -s` failed, and a copy cannot resolve its own library directory. It
  now writes a launcher stub instead, and verifies the symlink actually exists
  rather than trusting `ln`'s exit status. (#26)
- **An old shell shield kept a silent bypass.** An early version gated on
  `[ -t 1 ]`, so `npm install > log 2>&1` skipped the check entirely — and
  `shield install` refused to touch an existing block. It now detects an
  outdated block and refreshes it in place. (#27)
- **Hooks written before the version marker became invisible** to `status`,
  `uninstall` and `install`. Legacy hooks are now recognised and upgraded in
  place. (#27)
- `snare update` now reports what it could *not* update for you — a running
  guard, a stale shield, an old hook — instead of leaving stale copies running.
  (#27)
- `mktemp` templates are GNU-safe; without `XXXXXX` the scanner recorded no
  findings at all on Linux. (#16)
- `shasum` is no longer assumed present; without it every repository collided
  onto a single baseline key. (#29)
- Missing library files now produce one actionable message instead of thirteen
  cryptic errors. `SNARE_ROOT` overrides the location. (#26)

### Added

- `snare selftest` — asserts known-bad samples are flagged and known-good ones
  are not, including with `xxd` and `shasum` unavailable. Ten checks. (#5, #29)
- `snare update` — self-update, fast-forward only, refuses to discard local
  edits without `--force`. (#4)
- `snare shield` — scans before `npm`/`pnpm`/`yarn`/`bun`/`npx` and `git clone`
  can execute anything. (#18)
- `snare hook` — pre-push (and optional pre-commit) block, the only feature that
  prevents spread rather than detecting it afterwards. (#9)
- `snare ci` — writes a GitHub Actions workflow; a required status check is the
  closest thing to rejecting a push, since GitHub.com has no pre-receive hooks.
  (#15)
- `snare rotate` — what to revoke and in what order, plus a GitHub audit for the
  repositories and secret-exporting workflows this family leaves behind. npm
  write tokens first, because a stolen one is how a single machine becomes a
  supply-chain event. (#22)
- `snare report` / `snare schedule` — timestamped reports, `--json`, meaningful
  exit codes, and an opt-in timer. No email, deliberately. (#7)
- `snare baseline` — accept known findings so scheduled scans surface only what
  is new. Accepting a finding silences it; it does not make it safe. (#8)
- `snare fix --all` — dry run by default, and the confirmation requires typing
  the repository count. (#6)

### Changed

- `snare update --check` compares **commits**, not version strings. The version
  stood still for 33 commits, so a user 14 commits behind — carrying the font
  bug, the shield bypass and broken hook detection — was told "up to date".
- `snare version` reports the commit alongside the version.
- `snare ci` with no subcommand shows status instead of attempting an install.
- `snare help` documents every dispatched command; CI fails if one is missing.
- `require_gh` offers to run `gh auth login` when a human is present, and prints
  a platform-specific install command when `gh` is absent. Scripts, hooks,
  timers and CI keep the old message and exit code.
- shellcheck runs on every push; it found the guard evasion hole that eight
  rounds of manual review had missed.

## [1.0.0] — 2026-08-25

Initial release. Guard, repository and GitHub scanning, `fix`, `notify`.
