# Changelog

Versions follow [semantic versioning](https://semver.org). Anything that made
snare report **clean on an infected repository** is listed first in its release,
because that is the failure that matters most in a scanner.

`snare version` shows your version and commit. `snare update --check` compares
commits, not just version numbers.

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
