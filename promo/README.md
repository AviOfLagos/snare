# Promo drafts

Nothing here is published. Both drafts are ready to go out under your own name.

| File | Where it goes |
|---|---|
| `thread.py` / `thread.json` | 8-tweet thread. Already saved as a **draft** in Buffer. |
| `devto-article.md` | dev.to article, front matter included. Paste into a new post. |

## Twitter

The thread exists as a Buffer draft on the **Nexprove** channel. Review it in Buffer, then
publish from there. `python3 thread.py` re-checks every tweet against the 280-character limit
(URLs count as 23).

## dev.to

There is no API key configured, so this one is copy-paste:

1. https://dev.to/new
2. Paste `devto-article.md` whole — the front matter sets title, tags and canonical URL
3. `published: false` keeps it a draft until you flip it to `true` or hit Publish

`canonical_url` points at the field guide, so the site keeps the SEO value rather than
competing with the dev.to copy for it.

## After posting — one command

The site shows two greyed-out placeholder cards until the links exist. Swap them in:

```bash
cd docs
./set-links.sh --tweet https://x.com/YOU/status/123 --devto https://dev.to/YOU/slug
cd .. && git commit -am "site: add discussion links" && git push
```

Either flag on its own works, so you can add them as each post goes live. The script
rebuilds `index.html` for you; GitHub Pages redeploys about a minute after the push.

Edit by hand instead if you prefer — the placeholders are marked in `docs/src/index.html`:

```html
<!-- LINK:tweet:start -->  …  <!-- LINK:tweet:end -->
<!-- LINK:devto:start -->  …  <!-- LINK:devto:end -->
```

Never edit `docs/index.html` directly — it is generated, and `build.sh` overwrites it.
