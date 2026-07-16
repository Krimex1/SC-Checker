#!/usr/bin/env bash
# Cross-platform release build for SC Checker Go.
#
# Usage:
#   ./build.sh                  # build for the current OS/arch
#   GOOS=linux GOARCH=amd64 ./build.sh
#
# The resulting binary is written to ./sc-checker (or sc-checker.exe on Windows).
# CGO is required because of go-gl (OpenGL) used by the fyne GUI.

set -euo pipefail

cd "$(dirname "$0")"

GOOS="${GOOS:-$(go env GOOS)}"
GOARCH="${GOARCH:-$(go env GOARCH)}"

if [[ "${GOOS}" == "windows" ]]; then
	OUT="sc-checker.exe"
	EXTRA_LDFLAGS="-H windowsgui"
else
	OUT="sc-checker"
	EXTRA_LDFLAGS=""
fi

export CGO_ENABLED=1
export GOOS GOARCH

echo "[build] target:  ${GOOS}/${GOARCH}"
echo "[build] output:  ${OUT}"

go build \
	-ldflags="-s -w ${EXTRA_LDFLAGS}" \
	-trimpath \
	-buildvcs=false \
	-o "${OUT}" \
	./cmd/sc-checker

if command -v sha256sum >/dev/null 2>&1; then
	sha256sum "${OUT}" | tee "${OUT}.sha256"
else
	shasum -a 256 "${OUT}" | tee "${OUT}.sha256"
fi

echo
echo "[build] done"
