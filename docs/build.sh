#!/usr/bin/env bash
# build.sh — wrap the page fragment (_source.html) into a standalone document
# for GitHub Pages. The fragment is what gets published as a Claude Artifact,
# which supplies its own <head>; Pages needs the full document.
set -euo pipefail
cd "$(dirname "$0")"

SITE="https://avioflagos.github.io/snare/"
REPO="https://github.com/AviOfLagos/snare"
DESC="A supply-chain attack npm audit cannot see: the dropper is committed into the repository itself, not a dependency. Runs on git clone or when VS Code opens the folder. How it works, how to check your machine, and a free open-source scanner."

{
  echo '<!DOCTYPE html>'
  echo '<html lang="en">'
  echo '<head>'
  echo '<meta charset="utf-8">'
  echo '<meta name="viewport" content="width=device-width,initial-scale=1">'
  echo "<meta name=\"description\" content=\"$DESC\">"
  echo '<meta name="keywords" content="npm supply chain attack, supply chain malware, supply chain attack detection, npm malware, malicious npm package, compromised repository, repository malware scanner, shai-hulud, malicious postcss.config.js, vscode tasks.json malware, folderOpen exploit, EtherHiding, blockchain C2, fake woff2 payload, clipboard stealer, git history malware, npm audit missed, dependency security, developer security, open source security tool">'
  echo '<meta name="author" content="AviOfLagos">'
  echo '<meta name="robots" content="index,follow">'
  echo "<link rel=\"canonical\" href=\"$SITE\">"
  # Open Graph / Twitter
  echo '<meta property="og:type" content="website">'
  echo '<meta property="og:site_name" content="snare">'
  echo '<meta property="og:title" content="The supply-chain attack npm audit cannot see">'
  echo "<meta property=\"og:description\" content=\"A dropper family committed straight into developer repositories. It executes on the dev server or when your editor opens the folder — no npm install needed. Learn how it works, check your machine, and install snare.\">"
  echo "<meta property=\"og:url\" content=\"$SITE\">"
  echo '<meta name="twitter:card" content="summary_large_image">'
  echo '<meta name="twitter:title" content="The supply-chain attack npm audit cannot see">'
  echo '<meta name="twitter:description" content="Detect and remove supply-chain malware hidden in Git repositories. Free, open source, cross-platform.">'
  echo '<meta name="theme-color" content="#C2410C" media="(prefers-color-scheme: light)">'
  echo '<meta name="theme-color" content="#101319" media="(prefers-color-scheme: dark)">'
  echo '<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🪤</text></svg>">'
  # <title> and the font <link>s live at the top of the fragment
  sed -n '1,4p' _source.html
  # structured data helps this surface as a software result
  cat <<JSONLD
<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[
 {"@type":"SoftwareApplication","name":"snare",
  "applicationCategory":"SecurityApplication",
  "operatingSystem":"macOS, Linux, Windows, WSL",
  "description":"Command-line tool that detects and kills supply-chain malware loaders, scans every Git repository you can reach, removes the payload including from history, and notifies collaborators.",
  "url":"$SITE","codeRepository":"$REPO",
  "license":"https://opensource.org/licenses/MIT",
  "offers":{"@type":"Offer","price":"0","priceCurrency":"USD"}},
 {"@type":"TechArticle","headline":"Malware that runs the moment you open the project",
  "description":"$DESC","url":"$SITE",
  "author":{"@type":"Person","name":"AviOfLagos"}}
]}
</script>
JSONLD
  echo '</head>'
  echo '<body>'
  sed -n '5,$p' _source.html
  echo '</body>'
  echo '</html>'
} > index.html
echo "built index.html ($(wc -c < index.html) bytes)"
