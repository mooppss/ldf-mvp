#!/usr/bin/env bash
# Package LDF for shareware distribution: versioned zip + SHA256 checksums.
# The checksum file is the distribution's verification record (the paper's
# verifiable-artifact principle, applied to this project itself).
#
# The zip is `git archive` of HEAD: exactly the committed files, LF line
# endings on every platform, no `zip` binary needed. Commit before packaging.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON=$(command -v python3 || command -v python || true)
[ -n "$PYTHON" ] || { echo "release.sh: python3 not found" >&2; exit 1; }
VERSION=$(git show HEAD:ldf/__init__.py | "$PYTHON" -c \
    'import re, sys; print(re.search(r"__version__\s*=\s*\"([^\"]+)\"", sys.stdin.read()).group(1))')
NAME="ldf-mvp-${VERSION}"
DIST="dist"

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "warning: uncommitted changes are not packaged; building HEAD $(git rev-parse --short HEAD)" >&2
fi

mkdir -p "$DIST"
rm -f "$DIST/${NAME}.zip" "$DIST/SHA256SUMS"

git -c core.autocrlf=false archive --format=zip -o "$DIST/${NAME}.zip" HEAD

# Bare filename (run inside dist/) so `shasum -a 256 -c SHA256SUMS` works there;
# normalize the binary-mode marker some platforms emit ("<hash> *file").
if command -v shasum >/dev/null 2>&1; then
    SUM=$(cd "$DIST" && shasum -a 256 "${NAME}.zip")
else
    SUM=$(cd "$DIST" && sha256sum "${NAME}.zip")
fi
printf '%s\n' "${SUM/ \*/  }" > "$DIST/SHA256SUMS"

echo "packaged: ${DIST}/${NAME}.zip ($(du -h "$DIST/${NAME}.zip" | cut -f1)) from $(git rev-parse --short HEAD)"
echo "checksum: $(cat "$DIST/SHA256SUMS")"
echo ""
echo "verify after download:  shasum -a 256 -c SHA256SUMS"
