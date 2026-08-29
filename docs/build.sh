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
  # short label for breadcrumbs: the title up to its first em dash
  crumb="$(printf '%s' "$title" | sed 's/ *—.*//')"
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
<link rel="expect" href="#main" blocking="render">
<script>/* apply a pinned theme before first paint so the page never flashes */
try{var t=localStorage.getItem("snare-theme");if(t)document.documentElement.dataset.theme=t;}catch(e){}</script>
HEAD

    # Breadcrumbs on every page: gives a crawler the site hierarchy, and is
    # what produces the path shown under a search result.
    if [ "$out" != index.html ]; then
      cat <<CRUMB
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[
 {"@type":"ListItem","position":1,"name":"snare","item":"$SITE"},
 {"@type":"ListItem","position":2,"name":"$crumb","item":"$SITE$out"}]}
</script>
CRUMB
    fi

    # Page-specific structured data. A HowTo on the response walkthrough is the
    # one that matters: "how do I remove this malware" is what someone types
    # mid-incident, and HowTo is the type that answers it.
    case "$out" in
      infected.html)
        cat <<HOWTO
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"HowTo",
 "name":"Remove a committed supply-chain dropper from your repositories",
 "description":"$desc","url":"$SITE$out",
 "totalTime":"PT30M",
 "tool":[{"@type":"HowToTool","name":"snare"}],
 "step":[
  {"@type":"HowToStep","position":1,"name":"Rotate your credentials",
   "text":"Stealing credentials is the objective; removing the payload does not un-steal a token. Revoke npm write tokens first, then GitHub tokens, SSH keys and cloud keys.","url":"$SITE$out#rotate"},
  {"@type":"HowToStep","position":2,"name":"Clean the machine you push from",
   "text":"This family injects into commits as they leave an already-infected machine, so cleaning a repository first is wasted work.","url":"$SITE$out#machine"},
  {"@type":"HowToStep","position":3,"name":"Clean the repositories",
   "text":"snare fix is a dry run by default and always backs up first. Purging history rewrites every commit SHA, so every clone must be re-cloned rather than pulled.","url":"$SITE$out#repos"},
  {"@type":"HowToStep","position":4,"name":"Tell your collaborators",
   "text":"They may be infected from the same source, and a rewritten history breaks their clones without explanation.","url":"$SITE$out#notify"}]}
</script>
HOWTO
        ;;
      install.html)
        cat <<INST
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"SoftwareApplication","name":"snare",
 "applicationCategory":"SecurityApplication","operatingSystem":"macOS, Linux, Windows, WSL",
 "softwareVersion":"$VERSION","url":"$SITE$out","codeRepository":"$REPO",
 "license":"https://opensource.org/licenses/MIT",
 "description":"$desc",
 "offers":{"@type":"Offer","price":"0","priceCurrency":"USD"}}
</script>
INST
        ;;
      check.html)
        cat <<FAQ
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[
 {"@type":"Question","name":"How do I know if my machine is infected with this malware?",
  "acceptedAnswer":{"@type":"Answer","text":"Look for a node process running inline code with obfuscated globals, any file carrying the operator's wallet address, a .vscode/tasks.json task set to runOn folderOpen, and font files whose first four bytes are not a real font magic. A genuine .woff2 begins with wOF2."}},
 {"@type":"Question","name":"Does npm audit detect this?",
  "acceptedAnswer":{"@type":"Answer","text":"No. The dropper is committed into the repository itself rather than pulled from the registry, so there is no malicious dependency for npm audit, the lockfile or Dependabot to report."}},
 {"@type":"Question","name":"My process check came back clean. Am I safe?",
  "acceptedAnswer":{"@type":"Answer","text":"Not necessarily. The loader runs when a build runs or an editor opens the folder, then exits. A clean process check alongside infected repositories is the expected result, not a contradiction."}}]}
</script>
FAQ
        ;;
    esac

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
<header class="site-header">
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
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><line class="bar-top" x1="3" y1="6" x2="21" y2="6"/><line class="bar-mid" x1="3" y1="12" x2="21" y2="12"/><line class="bar-bot" x1="3" y1="18" x2="21" y2="18"/></svg>
      </button>
    </div>
  </div>
</nav>
</header>

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
    lm="$(date -u -r "$page" '+%Y-%m-%d' 2>/dev/null || date -u '+%Y-%m-%d')"
    printf '  <url><loc>%s</loc><lastmod>%s</lastmod><priority>%s</priority></url>\n' "$loc" "$lm" "$pri"
  done
  echo '</urlset>'
} > sitemap.xml

{
  echo '# snare — a free, open-source scanner for supply-chain malware'
  echo '# committed directly into git repositories.'
  echo '#'
  echo '# Everything here is public and free to index, quote and train on.'
  echo '# The whole point is that people find this before they are compromised,'
  echo '# so the crawlers below are named explicitly rather than left to infer'
  echo '# permission from the wildcard.'
  echo
  echo 'User-agent: *'
  echo 'Allow: /'
  echo
  for ua in Googlebot Bingbot DuckDuckBot Slurp Baiduspider YandexBot \
            GPTBot ChatGPT-User OAI-SearchBot ClaudeBot Claude-User \
            Claude-SearchBot anthropic-ai PerplexityBot Perplexity-User \
            Google-Extended Applebot Applebot-Extended Amazonbot Bytespider \
            CCBot cohere-ai Diffbot FacebookBot meta-externalagent \
            MistralAI-User TimpiBot YouBot; do
    echo "User-agent: $ua"
    echo 'Allow: /'
    echo
  done
  echo "Sitemap: ${SITE}sitemap.xml"
} > robots.txt

# llms.txt — the emerging convention for handing an AI assistant a compact,
# authoritative summary instead of leaving it to infer one from nine pages.
{
  cat <<LLMS
# snare

> A free, open-source command-line scanner for a supply-chain attack that
> \`npm audit\` cannot see: the dropper is committed directly into the git
> repository rather than pulled from the registry, so there is no malicious
> dependency, the lockfile is clean, and Dependabot has nothing to report.

Version ${VERSION}. MIT licensed. macOS, Linux, Windows (Git Bash) and WSL.
Needs bash, git, python3 and the GitHub CLI. Ships no credentials of its own
and uses the operator's own GitHub authentication.

## The threat

The payload is appended to a normal line in a build config after roughly 500
spaces, so the file looks untouched in an editor and in most diff views. It
executes on \`next dev\` or \`next build\`. A second variant uses a
\`.vscode/tasks.json\` task with \`"runOn": "folderOpen"\`, which fires the
moment the folder is opened in VS Code and runs a file disguised as a font — a
genuine .woff2 begins with the bytes wOF2. Neither route needs
\`npm install\`. The command-and-control address is read from the Ethereum
blockchain at runtime, so blocking one IP address achieves nothing.

Stealing credentials is the objective, not a side effect. The file in the
repository is delivery. Removing it does not un-steal a token.

## If someone is infected, the order matters

1. Rotate credentials first — npm write tokens before anything else, because a
   stolen one lets the worm publish trojanised versions of the victim's other
   packages under their own name.
2. Clean the machine they push from. This family injects into commits as they
   leave an already-infected machine, so cleaning a repository first is wasted
   work: it re-injects into whatever was just cleaned.
3. Then clean the repositories.
4. Then tell collaborators, who may be infected from the same source.

\`snare respond\` walks through all four, asking before every action.

## Two things people get wrong

- \`snare guard scan\` reporting "clean" does not mean the machine was never
  infected. The loader runs when a build runs or an editor opens the folder,
  and then exits.
- \`snare scan github\` reads branch tips through the API and cannot see
  history or build configs. \`snare scan repo\` against a real clone is the
  thorough check.

## Pages

- [Home](${SITE}): the threat, how it works, why npm audit misses it
- [Check your machine](${SITE}check.html): four commands, nothing to install
- [If you are infected](${SITE}infected.html): the response walkthrough
- [Install](${SITE}install.html): every platform, plus a prompt for AI assistants
- [Command reference](${SITE}commands.html): every command and its honest limits
- [Changelog](${SITE}changelog.html): every release, and what was broken before it
- [Report a bug](${SITE}security.html): false clean results wanted most of all
- [Community](${SITE}community.html): field reports and the open questions
- [Source](${REPO})
LLMS
} > llms.txt

echo "built $built pages + sitemap.xml, robots.txt, llms.txt (v$VERSION)"
