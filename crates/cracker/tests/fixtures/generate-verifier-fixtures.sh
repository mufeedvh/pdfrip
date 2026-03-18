#!/usr/bin/env bash
set -euo pipefail

# Regenerates the deterministic PDF security-handler fixture matrix used by the
# cracker integration tests. The generated files intentionally cover the
# password-based Standard Security Handler revisions that the prepared verifier
# supports in its direct password-verification path.

if ! command -v qpdf >/dev/null 2>&1; then
  echo "error: qpdf is required to generate cracker verifier fixtures" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required to generate cracker verifier fixtures" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}"
SOURCE_PDF="${OUTPUT_DIR}/source-minimal.pdf"
UNICODE_R5_PASSWORD="$(printf 'p\303\244ss-r5')"
UNICODE_R6_PASSWORD="$(printf 'p\303\244ss-r6')"

python3 - "$SOURCE_PDF" <<'PY'
from pathlib import Path
import sys

out = Path(sys.argv[1])
content_stream = b"BT\n/F1 24 Tf\n72 120 Td\n(PDFRip verifier fixture) Tj\nET\n"
objects = [
    b"<< /Type /Catalog /Pages 2 0 R >>\n",
    b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n",
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\n",
    f"<< /Length {len(content_stream)} >>\nstream\n".encode("ascii") + content_stream + b"endstream\n",
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n",
]

parts = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
offsets = []
for index, obj in enumerate(objects, start=1):
    offsets.append(sum(len(part) for part in parts))
    parts.append(f"{index} 0 obj\n".encode("ascii"))
    parts.append(obj)
    if not obj.endswith(b"\n"):
        parts.append(b"\n")
    parts.append(b"endobj\n")

xref_offset = sum(len(part) for part in parts)
parts.append(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
parts.append(b"0000000000 65535 f \n")
for offset in offsets:
    parts.append(f"{offset:010d} 00000 n \n".encode("ascii"))
parts.append(
    (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")
)

out.write_bytes(b"".join(parts))
PY

rm -f \
  "${OUTPUT_DIR}/r2-rc4.pdf" \
  "${OUTPUT_DIR}/r3-rc4.pdf" \
  "${OUTPUT_DIR}/r4-rc4.pdf" \
  "${OUTPUT_DIR}/r4-aes128.pdf" \
  "${OUTPUT_DIR}/r4-aes128-object-streams.pdf" \
  "${OUTPUT_DIR}/r4-aes128-linearized.pdf" \
  "${OUTPUT_DIR}/r4-aes128-cleartext-metadata.pdf" \
  "${OUTPUT_DIR}/r5-aes256.pdf" \
  "${OUTPUT_DIR}/r6-aes256.pdf" \
  "${OUTPUT_DIR}/r5-aes256-unicode.pdf" \
  "${OUTPUT_DIR}/r6-aes256-unicode.pdf" \
  "${OUTPUT_DIR}/r4-aes128-blank-user.pdf" \
  "${OUTPUT_DIR}/default-query-lower-a.pdf" \
  "${OUTPUT_DIR}/default-query-digit-0.pdf" \
  "${OUTPUT_DIR}/default-query-space.pdf" \
  "${OUTPUT_DIR}/mask-upper-digit.pdf" \
  "${OUTPUT_DIR}/contains-word-alice.pdf" \
  "${OUTPUT_DIR}/date-dot-format.pdf" \
  "${OUTPUT_DIR}/resume-late-mask.pdf"

qpdf --allow-weak-crypto --encrypt user-r2 owner-r2 40 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r2-rc4.pdf"
qpdf --allow-weak-crypto --encrypt user-r3 owner-r3 128 --use-aes=n -- "$SOURCE_PDF" "${OUTPUT_DIR}/r3-rc4.pdf"
qpdf --allow-weak-crypto --encrypt user-r4 owner-r4 128 --use-aes=n --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r4-rc4.pdf"
qpdf --allow-weak-crypto --encrypt user-r4a owner-r4a 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r4-aes128.pdf"
qpdf --allow-weak-crypto --min-version=1.5 --object-streams=generate --encrypt user-r4os owner-r4os 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r4-aes128-object-streams.pdf"
qpdf --allow-weak-crypto --linearize --encrypt user-r4lin owner-r4lin 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r4-aes128-linearized.pdf"
qpdf --allow-weak-crypto --encrypt user-r4meta owner-r4meta 128 --use-aes=y --force-V4 --cleartext-metadata -- "$SOURCE_PDF" "${OUTPUT_DIR}/r4-aes128-cleartext-metadata.pdf"
qpdf --encrypt user-r5 owner-r5 256 --force-R5 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r5-aes256.pdf"
qpdf --encrypt user-r6 owner-r6 256 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r6-aes256.pdf"
qpdf --encrypt "$UNICODE_R5_PASSWORD" owner-r5u 256 --force-R5 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r5-aes256-unicode.pdf"
qpdf --encrypt "$UNICODE_R6_PASSWORD" owner-r6u 256 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r6-aes256-unicode.pdf"
qpdf --allow-weak-crypto --encrypt '' owner-blank 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/r4-aes128-blank-user.pdf"
qpdf --allow-weak-crypto --encrypt a owner-dq-a 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/default-query-lower-a.pdf"
qpdf --allow-weak-crypto --encrypt 0 owner-dq-0 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/default-query-digit-0.pdf"
qpdf --allow-weak-crypto --encrypt ' ' owner-dq-space 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/default-query-space.pdf"
qpdf --allow-weak-crypto --encrypt AB12 owner-mask 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/mask-upper-digit.pdf"
qpdf --allow-weak-crypto --encrypt 0ALICE1 owner-contains 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/contains-word-alice.pdf"
qpdf --allow-weak-crypto --encrypt 15.01.2000 owner-date 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/date-dot-format.pdf"
qpdf --allow-weak-crypto --encrypt Z99 owner-resume 128 --use-aes=y --force-V4 -- "$SOURCE_PDF" "${OUTPUT_DIR}/resume-late-mask.pdf"

qpdf --password="$UNICODE_R5_PASSWORD" --check "${OUTPUT_DIR}/r5-aes256-unicode.pdf" >/dev/null
qpdf --show-encryption --password="$UNICODE_R5_PASSWORD" "${OUTPUT_DIR}/r5-aes256-unicode.pdf" | sed -n '1,4p'
qpdf --password="$UNICODE_R6_PASSWORD" --check "${OUTPUT_DIR}/r6-aes256-unicode.pdf" >/dev/null
qpdf --show-encryption --password="$UNICODE_R6_PASSWORD" "${OUTPUT_DIR}/r6-aes256-unicode.pdf" | sed -n '1,4p'

for pair in \
  "r2-rc4.pdf:user-r2" \
  "r3-rc4.pdf:user-r3" \
  "r4-rc4.pdf:user-r4" \
  "r4-aes128.pdf:user-r4a" \
  "r4-aes128-object-streams.pdf:user-r4os" \
  "r4-aes128-linearized.pdf:user-r4lin" \
  "r4-aes128-cleartext-metadata.pdf:user-r4meta" \
  "r5-aes256.pdf:user-r5" \
  "r6-aes256.pdf:user-r6" \
  "r4-aes128-blank-user.pdf:" \
  "default-query-lower-a.pdf:a" \
  "default-query-digit-0.pdf:0" \
  "default-query-space.pdf: " \
  "mask-upper-digit.pdf:AB12" \
  "contains-word-alice.pdf:0ALICE1" \
  "date-dot-format.pdf:15.01.2000" \
  "resume-late-mask.pdf:Z99"; do
  file="${pair%%:*}"
  password="${pair#*:}"
  qpdf --password="$password" --check "${OUTPUT_DIR}/${file}" >/dev/null
  qpdf --show-encryption --password="$password" "${OUTPUT_DIR}/${file}" | sed -n '1,4p'
done

echo "Generated cracker verifier fixtures in ${OUTPUT_DIR}"
