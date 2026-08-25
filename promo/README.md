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

## After posting

Add the live URLs to the site's Reports section so readers can find the discussion:

```
docs/_source.html  →  <div class="reports">
cd docs && ./build.sh && git commit && git push
```
