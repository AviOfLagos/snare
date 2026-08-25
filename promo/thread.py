TWEETS = [
"""A dropper is being committed straight into developer repos.

It runs when your editor opens the folder. Or when you start the dev server. No npm install needed.

One sample sat in a repo five months before anyone noticed.

How it works, and how to check yours 🧵""",

"""Route 1 — .vscode/tasks.json

A task labelled "eslint-check", marked hide:true, reveal:never, runOn:"folderOpen".

It runs: node ./public/fonts/fa-solid-400.woff2

That file is not a font. Real .woff2 starts with the bytes wOF2. This one starts with 507 spaces, then JavaScript.""",

"""Route 2 — postcss.config.js

Four normal lines of config. Then ~9,000 spaces on line 5. Then the payload.

Your editor shows you `};` and nothing else, because the rest is far off the right edge of the screen.

Runs on every next dev / next build.""",

"""Here's what makes IP blocklists useless.

The loader ships with no server address at all.

It reads a wallet's latest transaction off the Ethereum blockchain, decodes the first bytes of the destination address into an IPv4, and fetches stage two from there.

Known as EtherHiding.""",

"""So the operator repoints every infected machine at once, by sending one transaction.

Stage two is XOR-decoded and eval'd in memory. Nothing hits disk. Then spawn(detached)+unref() so it outlives the editor.

Observed payload: a clipboard stealer polling every 200ms.""",

"""Check your own machine. Takes a minute:

ps -eo pid,args | grep "node .*-e .*global\\["

grep -rn "0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a" .

grep -rn folderOpen .vscode/tasks.json

head -c 4 public/fonts/*.woff2

That last one must print wOF2. Spaces mean it's a script.""",

"""I built snare to do all of this: kills the loader on sight, scans every repo you can reach, purges the payload from git history, and helps you warn your collaborators.

Free, MIT, macOS / Linux / Windows.

Field guide → https://avioflagos.github.io/snare/
Code → https://github.com/AviOfLagos/snare""",

"""If this hit you or your team, please add what you saw.

Not to pile on anyone. The people who lost work to this had mostly never heard of the technique — and the ones who caught it early heard about it from someone else.

https://github.com/AviOfLagos/snare/issues/1""",
]

if __name__ == "__main__":
    ok = True
    for i, t in enumerate(TWEETS, 1):
        # X counts every URL as 23 chars
        import re
        n = len(re.sub(r'https?://\S+', 'x'*23, t))
        flag = "ok " if n <= 280 else "OVER"
        if n > 280: ok = False
        print(f"  {i}. {n:>3} chars  {flag}")
    print("\nthread fits" if ok else "\nFIX THE OVERSIZED TWEETS")
