#!/bin/sh
set -eu
umask 077

if [ "$#" -gt 1 ]; then
    printf 'Usage: sh %s [certificate-directory]\n' "$0" >&2
    exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
    printf 'OpenSSL is required to generate the local certificate.\n' >&2
    exit 1
fi

cert_dir=${1:-certs}
case "$cert_dir" in
    /*) ;;
    *) cert_dir="./$cert_dir" ;;
esac
cert_file="$cert_dir/server.crt"
key_file="$cert_dir/server.key"

if [ -L "$cert_dir" ] || { [ -e "$cert_dir" ] && [ ! -d "$cert_dir" ]; }; then
    printf 'Certificate destination must be a directory, not a file or symlink: %s\n' "$cert_dir" >&2
    exit 1
fi
if [ -e "$cert_file" ] || [ -L "$cert_file" ] || [ -e "$key_file" ] || [ -L "$key_file" ]; then
    printf 'Refusing to overwrite an existing certificate or key in %s; choose an empty directory.\n' "$cert_dir" >&2
    exit 1
fi

mkdir -p "$cert_dir"
chmod 0700 "$cert_dir"
temp_dir=$(mktemp -d "$cert_dir/.generate-local-cert.XXXXXX")
completed=false

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$completed" = false ]; then
        # Remove only files linked from our temporary directory, never another
        # invocation's files if it won the race to publish its certificate.
        for filename in server.key server.crt; do
            if [ "$temp_dir/$filename" -ef "$cert_dir/$filename" ]; then
                rm -f "$cert_dir/$filename"
            fi
        done
    fi
    rm -rf "$temp_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -sha256 -nodes -days 30 -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$temp_dir/server.key" -out "$temp_dir/server.crt"
chmod 0600 "$temp_dir/server.key"
chmod 0644 "$temp_dir/server.crt"

# Hard links publish complete files without replacing an existing destination.
if ! ln "$temp_dir/server.key" "$key_file"; then
    printf 'Could not install the private key without overwriting an existing file.\n' >&2
    exit 1
fi
if ! ln "$temp_dir/server.crt" "$cert_file"; then
    printf 'Could not install the certificate without overwriting an existing file.\n' >&2
    exit 1
fi
completed=true
printf 'Created local certificate: %s\nPrivate key: %s\nValid for 30 days.\n' "$cert_file" "$key_file"
