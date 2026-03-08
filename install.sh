#!/bin/sh
set -e

# envsh installer
# Usage: curl -fsSL https://get.envsh.dev | sh

REPO="envshq/envsh"
INSTALL_DIR="/usr/local/bin"
BINARY="envsh"

main() {
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$os" in
        darwin) os="darwin" ;;
        linux)  os="linux" ;;
        *)
            echo "Error: unsupported OS: $os"
            echo "envsh supports macOS and Linux. On Windows, use WSL."
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *)
            echo "Error: unsupported architecture: $arch"
            exit 1
            ;;
    esac

    if [ -n "$ENVSH_VERSION" ]; then
        version="$ENVSH_VERSION"
    else
        version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)"
        if [ -z "$version" ]; then
            echo "Error: could not determine latest version"
            exit 1
        fi
    fi

    filename="envsh_${version#v}_${os}_${arch}.tar.gz"
    url="https://github.com/${REPO}/releases/download/${version}/${filename}"

    echo "Installing envsh ${version} (${os}/${arch})..."

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    curl -fsSL "$url" -o "${tmpdir}/${filename}"
    tar -xzf "${tmpdir}/${filename}" -C "$tmpdir"

    if [ -w "$INSTALL_DIR" ]; then
        mv "${tmpdir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    else
        echo "Need sudo to install to ${INSTALL_DIR}"
        sudo mv "${tmpdir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    fi

    chmod +x "${INSTALL_DIR}/${BINARY}"

    echo "envsh ${version} installed to ${INSTALL_DIR}/${BINARY}"
    echo ""
    echo "Run 'envsh --help' to get started."
}

main
