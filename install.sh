
#!/bin/bash
set -euo pipefail

# Cloudflare Gateway CA installer for macOS
# Usage:
#   ./install.sh install
#   ./install.sh install --unattended
#   ./install.sh uninstall
#   ./install.sh status

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CERT="$SCRIPT_DIR/certs/cloudflare-gateway.pem"
KEYCHAIN="/Library/Keychains/System.keychain"
SECURITY="/usr/bin/security"
OPENSSL="/usr/bin/openssl"

# SHA-256 fingerprint of the expected certificate.
# Verify this independently against a trusted source before use.
EXPECTED_SHA256="5D:86:63:62:E0:43:3C:0E:4E:5B:74:00:E5:34:96:B8:16:37:BC:D6:4B:AA:C8:8C:F5:10:F4:2B:A8:1A:5B:07"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
RESET=$'\033[0m'

info()  { printf '%s\n' "$*"; }
ok()    { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
error() { printf '%sError:%s %s\n' "$RED" "$RESET" "$*" >&2; }

usage() {
    cat <<'EOF'
Cloudflare Gateway Certificate Manager

Usage:
  ./install.sh install
  ./install.sh install --unattended
  ./install.sh uninstall
  ./install.sh status

Commands:
  install                  Interactive installation
  install --unattended     Install without confirmation prompts
  uninstall                Remove this certificate and its trust settings
  status                   Check whether the certificate is installed
EOF
}

require_certificate() {
    if [[ ! -f "$CERT" ]]; then
        error "Certificate not found: $CERT"
        exit 1
    fi

    if ! "$OPENSSL" x509 -in "$CERT" -noout >/dev/null 2>&1; then
        error "The PEM file is not a valid X.509 certificate."
        exit 1
    fi

    ACTUAL_SHA256="$(
        "$OPENSSL" x509 -in "$CERT" -noout -fingerprint -sha256 |
        sed 's/^[^=]*=//'
    )"

    if [[ "$(printf '%s' "$ACTUAL_SHA256" | tr '[:lower:]' '[:upper:]')" != \
      "$(printf '%s' "$EXPECTED_SHA256" | tr '[:lower:]' '[:upper:]')" ]]; then
        error "Certificate fingerprint does not match the pinned fingerprint."
        info "Expected: $EXPECTED_SHA256"
        info "Actual:   $ACTUAL_SHA256"
        info "No changes have been made."
        exit 1
    fi

    # Require a CA certificate with CA:TRUE.
    if ! "$OPENSSL" x509 -in "$CERT" -noout -text |
        grep -q 'CA:TRUE'; then
        error "Certificate is not marked as a CA."
        exit 1
    fi
}

require_admin() {
    if [[ "$EUID" -ne 0 ]]; then
        info "Administrator privileges are required."
        exec sudo "$SCRIPT_PATH" "$@"
    fi
}

# Identify the certificate using its SHA-1 hash for Keychain lookup.
CERT_SHA1="$(
    "$OPENSSL" x509 -in "$CERT" -noout -fingerprint -sha1 |
    sed 's/^[^=]*=//; s/://g'
)"

is_installed() {
    "$SECURITY" find-certificate -a -Z "$KEYCHAIN" 2>/dev/null |
        grep -qiF "$CERT_SHA1"
}

show_details() {
    info "Certificate details:"
    "$OPENSSL" x509 -in "$CERT" -noout -subject -issuer -dates
    info "SHA-256: $ACTUAL_SHA256"
}

install_certificate() {
    local unattended="${1:-false}"

    require_certificate
    show_details

    if [[ "$unattended" != "true" ]]; then
        warn "This will trust a CA used for HTTPS traffic inspection."
        read -r -p "Have you independently verified this fingerprint? Type YES: " answer
        [[ "$answer" == "YES" ]] || {
            info "Cancelled."
            return 0
        }

        read -r -p "Install and trust this certificate? Type YES: " answer
        [[ "$answer" == "YES" ]] || {
            info "Cancelled."
            return 0
        }
    fi

    require_admin "$@"

    if is_installed; then
        ok "Certificate already exists in the System keychain."
        info "No duplicate certificate was added."
        return 0
    fi

    "$SECURITY" add-trusted-cert \
        -d \
        -r trustRoot \
        -k "$KEYCHAIN" \
        "$CERT"

    if is_installed; then
        ok "Certificate installed in the System keychain."
    else
        error "Installation could not be verified."
        exit 1
    fi
}

uninstall_certificate() {
    require_certificate
    show_details

    read -r -p "Remove this certificate and its trust settings? Type YES: " answer
    [[ "$answer" == "YES" ]] || {
        info "Cancelled."
        return 0
    }

    require_admin "$@"

    if ! is_installed; then
        warn "Certificate is not present in the System keychain."
        info "Checking/removing any matching trust settings."
    fi

    # Remove the trust configuration for this certificate.
    "$SECURITY" remove-trusted-cert "$CERT" 2>/dev/null || true

    # Delete only the exact certificate identified by its SHA-1 hash.
    if is_installed; then
        "$SECURITY" delete-certificate -Z "$CERT_SHA1" "$KEYCHAIN"
    fi

    if is_installed; then
        error "Certificate still appears in the System keychain."
        exit 1
    fi

    ok "Removal completed. Verify trust settings in Keychain Access."
}

status() {
    require_certificate
    show_details

    if is_installed; then
        ok "Matching certificate exists in the System keychain."
        info "This does not by itself prove that every trust setting is correct."
    else
        warn "Certificate is not present in the System keychain."
    fi
}

SCRIPT_PATH="$SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")"

COMMAND="${1:-}"
case "$COMMAND" in
    install)
        MODE="${2:-}"
        if [[ "$MODE" == "--unattended" ]]; then
            install_certificate true "$@"
        elif [[ -z "$MODE" ]]; then
            install_certificate false "$@"
        else
            usage
            exit 2
        fi
        ;;
    uninstall)
        uninstall_certificate "$@"
        ;;
    status)
        status
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 2
        ;;
esac
