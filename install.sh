#!/usr/bin/env bash
# install.sh — put snare on your PATH. Installs nothing else, ships no credentials.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SNARE_BIN:-$HOME/.local/bin}"

echo "snare installer"
echo "  source: $SRC"

miss=0
for c in bash git python3; do
  command -v "$c" >/dev/null || { echo "  MISSING: $c"; miss=1; }
done
command -v gh >/dev/null || { echo "  MISSING: gh (GitHub CLI) — brew install gh"; miss=1; }
command -v git-filter-repo >/dev/null || echo "  optional: git-filter-repo not found (needed only for --purge-history)"
[ "$miss" = 1 ] && { echo "install the missing tools first"; exit 1; }

mkdir -p "$BIN"
ln -sf "$SRC/bin/snare" "$BIN/snare"
chmod +x "$SRC/bin/snare"
echo "  linked: $BIN/snare -> $SRC/bin/snare"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo
     echo "  $BIN is not on your PATH. Add this to ~/.zshrc:"
     echo "      export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

cat <<'NEXT'

Done. Next:

  gh auth login          authenticate with YOUR OWN GitHub account
  snare doctor           check this machine and your account
  snare scan github      scan every repo you can reach
  snare guard install    kill the loader on sight, from login onwards

snare never ships or stores a token. It uses your gh credentials.
NEXT
