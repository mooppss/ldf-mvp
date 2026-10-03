#!/usr/bin/env bash
# Package LDF for shareware distribution: versioned zip + SHA256 checksums.
# The checksum file is the distribution's verification record (the paper's
# verifiable-artifact principle, applied to this project itself).
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(python3 - <<'PY'
import sys; sys.path.insert(0, ".")
try:
    import ldf
    print(ldf.__version__)
except Exception:
    print("0.1.0")
PY
)
NAME="ldf-mvp-${VERSION}"
DIST="dist"
mkdir -p "$DIST"
rm -f "$DIST/${NAME}.zip" "$DIST/SHA256SUMS"

zip -qr "$DIST/${NAME}.zip" . \
    -x "*.pyc" -x "*__pycache__*" -x "*.DS_Store" -x ".git/*" -x ".git" \
    -x ".pytest_cache/*" -x "dist/*" -x "htmlcov/*" -x ".coverage*"

shasum -a 256 "$DIST/${NAME}.zip" > "$DIST/SHA256SUMS"

echo "packaged: ${DIST}/${NAME}.zip ($(du -h "$DIST/${NAME}.zip" | cut -f1))"
echo "checksum: $(cat "$DIST/SHA256SUMS")"
echo ""
echo "verify after download:  shasum -a 256 -c SHA256SUMS"