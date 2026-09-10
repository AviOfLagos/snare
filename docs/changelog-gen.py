#!/usr/bin/env python3
"""Render CHANGELOG.md into the changelog page body.

The release notes used to be written twice — once in CHANGELOG.md and once as
hand-written HTML in docs/src/changelog.html — which meant they could disagree,
and the website could tell someone a fix had shipped when it had not. This
makes CHANGELOG.md the single source: update it in a pull request and the site
follows on the next build.

Mapping:
    ## [1.2.0] — 2026-09-10   -> a release section, newest marked "Current"
    ### Fixed — ...           -> a group heading; "false clean" or "destructive"
                                 marks the group and its items critical, because
                                 those are the failures that matter most here
    - **Lead.** body (#41)    -> a list item, refs linked to the pull request
    `code`  **bold**  *em*    -> <code> <strong> <em>
"""
import html
import re
import sys

REPO = "https://github.com/AviOfLagos/snare"


def inline(text: str) -> str:
    """Escape, then re-introduce the small set of inline markup we allow."""
    t = html.escape(text, quote=False)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", t)
    # (#41) and (#33, #34) -> links. @user -> a profile link.
    def refs(m):
        nums = re.findall(r"#(\d+)", m.group(1))
        if not nums:
            return m.group(0)
        joined = ", ".join(f"#{n}" for n in nums)
        return f' <a href="{REPO}/pull/{nums[0]}">{joined}</a>'
    t = re.sub(r"\s*\(((?:#\d+(?:,\s*)?)+)\)", refs, t)
    t = re.sub(r"@([A-Za-z0-9-]+)", r'<a href="https://github.com/\1">@\1</a>', t)
    return t


def slug(v: str) -> str:
    return "v" + v.replace(".", "-")


def is_critical(heading: str) -> bool:
    h = heading.lower()
    return "false clean" in h or "destructive" in h


def parse(md: str):
    """-> [ {version, date, lede, groups:[{title, critical, items:[str]}]} ]"""
    releases, cur, group = [], None, None
    lede_lines, item = [], None

    def flush_item():
        nonlocal item
        if item is not None and group is not None:
            group["items"].append(" ".join(item).strip())
        item = None

    def flush_lede():
        nonlocal lede_lines
        if cur is not None and lede_lines and not cur["lede"]:
            cur["lede"] = " ".join(lede_lines).strip()
        lede_lines = []

    for raw in md.split("\n"):
        line = raw.rstrip()
        m = re.match(r"^## \[([0-9][0-9.]*)\]\s*—\s*(.+)$", line)
        if m:
            flush_item(); flush_lede()
            cur = {"version": m.group(1), "date": m.group(2).strip(),
                   "lede": "", "groups": []}
            releases.append(cur); group = None
            continue
        if cur is None:
            continue
        m = re.match(r"^### (.+)$", line)
        if m:
            flush_item(); flush_lede()
            group = {"title": m.group(1).strip(),
                     "critical": is_critical(m.group(1)), "items": []}
            cur["groups"].append(group)
            continue
        m = re.match(r"^- (.+)$", line)
        if m:
            flush_item()
            item = [m.group(1)]
            continue
        if item is not None and line.startswith("  ") and line.strip():
            item.append(line.strip())          # continuation of a list item
            continue
        if line.strip():
            if group is None:
                lede_lines.append(line.strip())  # prose under the release
        else:
            flush_item()
    flush_item(); flush_lede()
    return releases


def render(releases) -> str:
    out = []
    for i, r in enumerate(releases):
        tag = '\n        <span class="tag now">Current</span>' if i == 0 else ""
        out.append(f'<section class="stack" id="{slug(r["version"])}">')
        out.append('  <div class="rel">')
        out.append('    <div class="rel-head">')
        out.append(f'      <h2 class="rel-v">{html.escape(r["version"])}</h2>')
        out.append(f'      <span class="rel-date">{html.escape(r["date"])}</span>{tag}')
        out.append('    </div>')
        if r["lede"]:
            out.append(f'    <p class="lede">{inline(r["lede"])}</p>')
        for g in r["groups"]:
            cls = ' class="crit"' if g["critical"] else ""
            out.append('    <div class="rel-group">')
            out.append(f'      <h3{cls}>{inline(g["title"])}</h3>')
            out.append('      <ul class="rel-list">')
            for it in g["items"]:
                out.append(f'        <li{cls}>{inline(it)}</li>')
            out.append('      </ul>')
            out.append('    </div>')
        out.append('  </div>')
        out.append('</section>')
    return "\n".join(out)


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "../CHANGELOG.md"
    rels = parse(open(src).read())
    if not rels:
        sys.exit("changelog-gen: no releases parsed from " + src)
    sys.stdout.write(render(rels) + "\n")
