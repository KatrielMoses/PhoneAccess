#!/bin/bash
set -e

REPO="KatrielMoses/PhoneAccess"
VERSION="v1.0.1"
ARCH=$(uname -m)

case $ARCH in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

echo "Installing PhoneAccess $VERSION for ${OS}/$ARCH..."

if [ "$OS" = "linux" ] && command -v dpkg &>/dev/null; then
  PKG_URL="$BASE_URL/phoneaccess_linux_${ARCH}.deb"
  echo "Detected Debian/Ubuntu — installing .deb"
  curl -fsSL "$PKG_URL" -o /tmp/phoneaccess.deb
  sudo dpkg -i /tmp/phoneaccess.deb
  rm -f /tmp/phoneaccess.deb
elif [ "$OS" = "linux" ] && command -v rpm &>/dev/null; then
  PKG_URL="$BASE_URL/phoneaccess_linux_${ARCH}.rpm"
  echo "Detected Fedora/RHEL — installing .rpm"
  curl -fsSL "$PKG_URL" -o /tmp/phoneaccess.rpm
  sudo rpm -i /tmp/phoneaccess.rpm
  rm -f /tmp/phoneaccess.rpm
else
  BIN_URL="$BASE_URL/phoneaccess_${OS}_${ARCH}"
  DEST="/usr/local/bin/phoneaccess"
  echo "Installing binary to $DEST"
  curl -fsSL "$BIN_URL" -o /tmp/phoneaccess
  chmod +x /tmp/phoneaccess
  sudo mv /tmp/phoneaccess "$DEST"
fi

echo "Done. Run: phoneaccess version"
