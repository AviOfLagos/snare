#!/usr/bin/env bash
# install.sh — put snare on your PATH. Ships no credentials, installs nothing else.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -s 2>/dev/null)" in
  Darwin) OS=macos ;;
  Linux)  grep -qi microsoft /proc/version 2>/dev/null && OS=wsl || OS=linux ;;
  MINGW*|MSYS*|CYGWIN*) OS=windows ;;
  *) OS=unknown ;;
esac

BIN="${SNARE_BIN:-$HOME/.local/bin}"
echo "snare installer"
echo "  platform: $OS"
echo "  source:   $SRC"
echo

# ---- required ------------------------------------------------------------
miss=0
for c in bash git python3; do
  if command -v "$c" >/dev/null 2>&1; then printf '  ok       %s\n' "$c"
  else printf '  MISSING  %s\n' "$c"; miss=1; fi
done
if command -v gh >/dev/null 2>&1; then printf '  ok       gh\n'
else
  printf '  MISSING  gh (GitHub CLI)\n'; miss=1
fi

# ---- optional ------------------------------------------------------------
command -v git-filter-repo >/dev/null 2>&1 \
  && printf '  ok       git-filter-repo\n' \
  || printf '  optional git-filter-repo  (only for: snare fix --purge-history)\n'
case "$OS" in
  linux|wsl)
    command -v systemctl   >/dev/null 2>&1 || printf '  optional systemd  (else run the guard yourself)\n'
    command -v notify-send >/dev/null 2>&1 || printf '  optional libnotify (desktop alerts)\n'
    command -v xdg-open    >/dev/null 2>&1 || printf '  optional xdg-utils (opening mail drafts)\n' ;;
esac

if [ "$miss" = 1 ]; then
  echo
  echo "Install what is missing, then re-run:"
  case "$OS" in
    macos)   echo "  brew install git gh python3" ;;
    linux|wsl)
      echo "  Debian/Ubuntu:  sudo apt install -y git python3 curl"
      echo "                  (gh: https://github.com/cli/cli/blob/trunk/docs/install_linux.md)"
      echo "  Fedora:         sudo dnf install -y git python3 gh"
      echo "  Arch:           sudo pacman -S git python github-cli" ;;
    windows) echo "  winget install Git.Git GitHub.cli Python.Python.3.12"
             echo "  then run this from Git Bash (not cmd/PowerShell)" ;;
  esac
  exit 1
fi

mkdir -p "$BIN"
# Prefer a symlink. Where symlinks are unavailable — Windows Git Bash, most
# often — write a launcher stub that execs the real script in place. Copying
# the script itself does NOT work: it resolves its lib/ directory relative to
# its own location, so a copy in ~/.local/bin looks for ~/.local/lib and fails
# with a dozen "No such file or directory" lines.
_linked=""
if ln -sf "$SRC/bin/snare" "$BIN/snare" 2>/dev/null && [ -L "$BIN/snare" ]; then
  _linked="linked"
else
  rm -f "$BIN/snare" 2>/dev/null
  cat > "$BIN/snare" <<LAUNCHER
#!/usr/bin/env bash
# snare launcher. This platform does not support symlinks, so this stub execs
# the real script from the checkout. Regenerate it by re-running install.sh.
exec "$SRC/bin/snare" "\$@"
LAUNCHER
  _linked="launcher"
fi
chmod +x "$SRC/bin/snare" "$BIN/snare" 2>/dev/null
echo
if [ "$_linked" = linked ]; then
  echo "  linked: $BIN/snare -> $SRC/bin/snare"
else
  echo "  launcher: $BIN/snare -> $SRC/bin/snare"
  echo "            (symlinks unavailable on this platform; a stub was written instead)"
fi

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo
     echo "  $BIN is not on your PATH — add to your shell profile:"
     echo "      export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

cat <<NEXT

Done. Next:

  gh auth login          authenticate with YOUR OWN GitHub account
  snare doctor           check this machine and your account
  snare scan github      scan every repo you can reach
  snare guard install    kill the loader on sight, from login onwards

snare never ships or stores a token — it uses your gh credentials.
NEXT

case "$OS" in
  windows) echo
           echo "Windows note: run snare from Git Bash or WSL."
           echo "'snare guard install' registers a logon Scheduled Task." ;;
  wsl)     echo
           echo "WSL note: the guard only sees processes inside WSL," 
           echo "not those running on Windows itself." ;;
esac
