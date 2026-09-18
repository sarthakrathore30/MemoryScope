"""
File format and integrity validation for uploaded memory images.

Covers:
  FR-2 - reject unsupported/corrupted files
  TC-AC-02 - corrupted/truncated file rejection
  TC-AC-03 - unsupported file type rejection
"""
import os

from acquisition.exceptions import UnsupportedFormatError, CorruptedImageError

# Common raw memory image extensions accepted by Volatility 3.
ALLOWED_EXTENSIONS = {".raw", ".mem", ".dmp", ".vmem", ".img", ".bin", ".lime"}

# Magic-byte signatures for formats that actually have one, checked as a
# best-effort defense against an executable or other file type being
# disguised by simply renaming its extension.
#
# This is necessarily partial: raw physical memory dumps (.raw, .vmem,
# .img, .bin, .mem) have NO defined file header at all -- they are just a
# flat byte stream starting with whatever the first bytes of RAM happened
# to be, so there is nothing to validate a signature against for those
# extensions. Only the two formats below have an actual documented header:
#   - Windows crash dumps (.dmp): "PAGEDUMP" (32-bit) or "PAGEDU64" (64-bit)
#     at offset 0 -- documented, high-confidence.
#   - LiME (.lime): a little-endian uint32 magic 0x4c694d45 at offset 0,
#     which serializes to the ASCII bytes "EMiL" -- included in good faith
#     based on the LiME source format, but has not been verified against a
#     real captured .lime file in this environment; treat with somewhat
#     lower confidence than the crash dump check.
MAGIC_SIGNATURES = {
    ".dmp": [b"PAGEDUMP", b"PAGEDU64"],
    ".lime": [b"EMiL"],
}

# A legitimate memory dump is expected to be at least this large. This is a
# heuristic guard against obviously truncated/placeholder files, not a
# substitute for real forensic integrity verification.
MIN_VALID_SIZE_BYTES = 1 * 1024 * 1024  # 1 MB

# Upper bound on accepted memory image size. Generous enough for real-world
# RAM captures (even high-memory servers) while preventing an unbounded
# upload from exhausting disk space -- enforced DURING the streaming write
# in acquisition.service.save_uploaded_file, not just checked afterward,
# so a malicious/mistaken huge upload is aborted early rather than filling
# the disk first and only being rejected once fully written.
MAX_VALID_SIZE_BYTES = 64 * 1024 * 1024 * 1024  # 64 GB


def validate_extension(filename: str) -> str:
    """
    Validate the file extension against the allow-list.

    Returns the lowercase extension on success.
    Raises UnsupportedFormatError otherwise (TC-AC-03).
    """
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise UnsupportedFormatError(
            f"Unsupported file format '{ext or '(none)'}'. "
            f"Allowed formats: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )
    return ext


def validate_signature(file_path: str, ext: str) -> None:
    """
    Best-effort magic-byte check for extensions that have a defined file
    signature (see MAGIC_SIGNATURES). Extensions with no defined signature
    (raw physical memory dumps have no header at all) are silently skipped
    -- this is a real, honest limitation of validating this file format
    family, not an oversight.

    Raises UnsupportedFormatError if the extension has a known signature
    and the file's actual header doesn't match it (TC-AC-03: e.g. an
    executable renamed to case.dmp).
    """
    expected_signatures = MAGIC_SIGNATURES.get(ext)
    if not expected_signatures:
        return

    max_len = max(len(sig) for sig in expected_signatures)
    with open(file_path, "rb") as f:
        header = f.read(max_len)

    if not any(header.startswith(sig) for sig in expected_signatures):
        raise UnsupportedFormatError(
            f"File does not have a valid {ext} header signature. "
            "It may be a different file type disguised with this extension."
        )


def validate_integrity(file_path: str) -> None:
    """
    Perform basic integrity checks on a saved memory image file.

    Raises CorruptedImageError if the file is missing, empty, or
    suspiciously small/truncated (TC-AC-02).
    """
    if not os.path.exists(file_path):
        raise CorruptedImageError("Uploaded file could not be found on disk after save.")

    size = os.path.getsize(file_path)
    if size == 0:
        raise CorruptedImageError("Uploaded file is empty.")

    if size < MIN_VALID_SIZE_BYTES:
        raise CorruptedImageError(
            f"Uploaded file is only {size} bytes, which is too small to be a "
            f"valid memory image (minimum expected: {MIN_VALID_SIZE_BYTES} bytes). "
            "The file may be truncated or corrupted."
        )

    if size > MAX_VALID_SIZE_BYTES:
        raise CorruptedImageError(
            f"Uploaded file is {size} bytes, which exceeds the maximum accepted "
            f"size ({MAX_VALID_SIZE_BYTES} bytes)."
        )


def validate_memory_image(filename: str, file_path: str) -> str:
    """
    Run full validation pipeline: extension check, then integrity check,
    then best-effort signature check where one exists.

    Returns the validated extension. Raises UnsupportedFormatError or
    CorruptedImageError on failure.
    """
    ext = validate_extension(filename)
    validate_integrity(file_path)
    validate_signature(file_path, ext)
    return ext
