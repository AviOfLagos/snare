#!/usr/bin/env bash
# build.sh — assemble the static site from the fragments in src/.
#
# Each src/<name>.html carries its own metadata in leading comments:
#
#   <!--#title: ...-->    <title> and og:title
#   <!--#desc: ...-->     meta description and og:description
#   <!--#nav: ...-->      which primary nav item is current (or "none")
#   <!--#prev: file.html|Label-->
#   <!--#next: file.html|Label-->
#
# Everything after the metadata block is the page body. The nav, the footer
# and the <head> are defined once here, so a nav change is a one-line edit
# rather than a find-and-replace across seven files.
set -euo pipefail
cd "$(dirname "$0")"

SITE="https://avioflagos.github.io/snare/"
REPO="https://github.com/AviOfLagos/snare"
VERSION="$(sed -n 's/^## \[\([0-9.]*\)\].*/\1/p' ../CHANGELOG.md | head -1)"
[ -n "$VERSION" ] || { echo "could not read version from ../CHANGELOG.md" >&2; exit 1; }

# nav order doubles as the reading order for the prev/next pager
NAV_KEYS=(index check infected install docs community)
nav_href(){ case "$1" in
  index) echo "index.html";; check) echo "check.html";; infected) echo "infected.html";;
  install) echo "install.html";; docs) echo "docs.html";; community) echo "community.html";; esac; }
nav_label(){ case "$1" in
  index) echo "The threat";; check) echo "Check";; infected) echo "If infected";;
  install) echo "Install";; docs) echo "Docs";; community) echo "Community";; esac; }

meta(){ sed -n "s/^<!--#$1: \(.*\)-->$/\1/p" "$2" | head -1; }

build_page(){
  local src="$1" out title desc navkey prev next
  out="$(basename "$src")"
  title="$(meta title "$src")"
  desc="$(meta desc "$src")"
  navkey="$(meta nav "$src")"
  prev="$(meta prev "$src")"
  next="$(meta next "$src")"

  {
    cat <<HEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$title</title>
<meta name="description" content="$desc">
<meta name="author" content="AviOfLagos">
<meta name="robots" content="index,follow">
<link rel="canonical" href="$SITE$([ "$out" = index.html ] || echo "$out")">
<meta property="og:type" content="website">
<meta property="og:site_name" content="snare">
<meta property="og:title" content="$title">
<meta property="og:description" content="$desc">
<meta property="og:url" content="$SITE$([ "$out" = index.html ] || echo "$out")">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="$title">
<meta name="twitter:description" content="$desc">
<meta name="theme-color" content="#C2410C" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#101319" media="(prefers-color-scheme: dark)">
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🪤</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;12..96,600;12..96,800&family=Instrument+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap">
<link rel="stylesheet" href="assets/site.css">
<script>/* apply a pinned theme before first paint so the page never flashes */
try{var t=localStorage.getItem("snare-theme");if(t)document.documentElement.dataset.theme=t;}catch(e){}</script>
HEAD

    # keyword + structured data only on the entry page
    if [ "$out" = index.html ]; then
      cat <<'KW'
<meta name="keywords" content="npm supply chain attack, supply chain malware, supply chain attack detection, npm malware, malicious npm package, compromised repository, repository malware scanner, shai-hulud, malicious postcss.config.js, vscode tasks.json malware, folderOpen exploit, EtherHiding, blockchain C2, fake woff2 payload, clipboard stealer, git history malware, npm audit missed, dependency security, developer security, open source security tool">
KW
      cat <<JSONLD
<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[
 {"@type":"SoftwareApplication","name":"snare",
  "applicationCategory":"SecurityApplication",
  "operatingSystem":"macOS, Linux, Windows, WSL",
  "softwareVersion":"$VERSION",
  "description":"Command-line tool that detects and kills supply-chain malware loaders, scans every Git repository you can reach, removes the payload including from history, and notifies collaborators.",
  "url":"$SITE","codeRepository":"$REPO",
  "license":"https://opensource.org/licenses/MIT",
  "offers":{"@type":"Offer","price":"0","priceCurrency":"USD"}},
 {"@type":"TechArticle","headline":"Malware that runs the moment you open the project",
  "description":"$desc","url":"$SITE",
  "author":{"@type":"Person","name":"AviOfLagos"}}
]}
</script>
JSONLD
    fi

    echo '</head>'
    echo "<body data-page=\"${out%.html}\">"
    echo '<a class="skip" href="#main">Skip to content</a>'

    # ---- nav ----
    cat <<'NAVTOP'
<nav class="nav" aria-label="Primary">
  <div class="nav-in">
    <a class="brand" href="index.html"><span class="mark">sn</span>snare</a>
NAVTOP
    echo "    <a class=\"ver\" href=\"changelog.html\" title=\"What changed in v$VERSION\">v$VERSION</a>"
    echo '    <div class="nav-links" id="nav-links">'
    for k in "${NAV_KEYS[@]}"; do
      if [ "$k" = "$navkey" ]; then
        echo "      <a href=\"$(nav_href "$k")\" aria-current=\"page\">$(nav_label "$k")</a>"
      else
        echo "      <a href=\"$(nav_href "$k")\">$(nav_label "$k")</a>"
      fi
    done
    cat <<'NAVBOT'
      <a class="nav-cta" href="install.html">Install snare</a>
    </div>
    <div class="nav-tools">
      <button class="icon-btn theme-toggle" type="button" aria-label="Switch theme">
        <svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
        <svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>
      </button>
      <button class="icon-btn nav-toggle" type="button" aria-expanded="false" aria-controls="nav-links" aria-label="Open menu">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M3 6h18M3 12h18M3 18h18"/></svg>
      </button>
    </div>
  </div>
</nav>

<main id="main">
NAVBOT

    # ---- body ----
    grep -v '^<!--#' "$src"

    # ---- pager ----
    if [ -n "$prev" ] || [ -n "$next" ]; then
      echo '<div class="wrap"><nav class="pager" aria-label="Page">'
      [ -n "$prev" ] && printf '  <a href="%s"><span class="dir">← Previous</span><b>%s</b></a>\n' "${prev%%|*}" "${prev#*|}"
      [ -n "$next" ] && printf '  <a class="next-a" href="%s"><span class="dir">Next →</span><b>%s</b></a>\n' "${next%%|*}" "${next#*|}"
      echo '</nav></div>'
    fi

    # ---- footer ----
    cat <<FOOT
</main>

<div class="wrap">
<footer>
  <div class="foot-grid">
    <div class="foot-col">
      <b>snare</b>
      <p class="foot-note">Free and open source under the MIT licence. Indicators and analysis are
      published so other developers can detect this family in their own repositories. Payload
      excerpts are truncated and defanged.</p>
    </div>
    <div class="foot-col">
      <b>The threat</b>
      <a href="index.html">How it works</a>
      <a href="check.html">Check your machine</a>
      <a href="infected.html">If you're infected</a>
    </div>
    <div class="foot-col">
      <b>The tool</b>
      <a href="install.html">Install</a>
      <a href="docs.html">Documentation</a>
      <a href="commands.html">Command reference</a>
      <a href="changelog.html">Changelog</a>
      <a href="community.html">Community</a>
      <a href="security.html">Report a bug</a>
    </div>
  </div>
  <div class="foot-bar">
    <span>Findings from a first-hand investigation, August 2026.</span>
    <span><a href="$REPO">github.com/AviOfLagos/snare</a> · <a href="changelog.html">v$VERSION</a> · MIT</span>
  </div>
</footer>
</div>

<script src="assets/site.js"></script>
</body>
</html>
FOOT
  } > "$out"
  printf '  %-18s %6s bytes\n' "$out" "$(wc -c < "$out" | tr -d ' ')"
}

built=0
for f in src/*.html; do
  build_page "$f"
  built=$((built + 1))
done

# ---- sitemap + robots ----
# Split into pages, the site needs to tell crawlers what exists; a single scroll
# page did not. Priority follows the reading order the nav implies.
{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
  for page in index.html check.html infected.html install.html docs.html commands.html community.html changelog.html security.html; do
    [ -f "$page" ] || continue
    case "$page" in
      index.html) loc="$SITE"; pri="1.0" ;;
      check.html|install.html|docs.html) loc="$SITE$page"; pri="0.9" ;;
      infected.html|commands.html|community.html) loc="$SITE$page"; pri="0.8" ;;
      *) loc="$SITE$page"; pri="0.6" ;;
    esac
    printf '  <url><loc>%s</loc><priority>%s</priority></url>\n' "$loc" "$pri"
  done
  echo '</urlset>'
} > sitemap.xml

{
  echo 'User-agent: *'
  echo 'Allow: /'
  echo "Sitemap: ${SITE}sitemap.xml"
} > robots.txt

echo "built $built pages + sitemap.xml, robots.txt (v$VERSION)"
