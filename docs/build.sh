#!/usr/bin/env bash
# build.sh — wrap the artifact fragment into a standalone page for GitHub Pages.
set -euo pipefail
cd "$(dirname "$0")"
{
  echo '<!DOCTYPE html>'
  echo '<html lang="en">'
  echo '<head>'
  echo '<meta charset="utf-8">'
  echo '<meta name="viewport" content="width=device-width,initial-scale=1">'
  echo '<meta name="description" content="How a supply-chain dropper hid behind 9,000 spaces, how to find it by hand, and how to install snare.">'
  echo '<meta property="og:title" content="Hidden in Whitespace">'
  echo '<meta property="og:description" content="A dropper committed into four repositories. The config file looked normal in every editor that opened it.">'
  echo '<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🪤</text></svg>">'
  # <title> and font <link> live at the top of the fragment
  sed -n '1,5p' _source.html
  echo '</head>'
  echo '<body>'
  sed -n '6,$p' _source.html
  echo '</body>'
  echo '</html>'
} > index.html
echo "built index.html ($(wc -c < index.html) bytes)"
