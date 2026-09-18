"""
YARA-based signature scanning (FR-12, FR-13, FR-14, TC-DT-02, TC-DT-03).

Rules are loaded from an external, configurable directory (not hardcoded),
so an administrator can add/update rules without touching source code
(FR-14). Scanning targets raw bytes -- in the full pipeline these bytes come
from process memory regions or dumped module artifacts extracted by the
Analysis module; for unit testing they can be any bytes/file.
"""
import os
import tempfile
from dataclasses import dataclass
from typing import List, Optional

import yara

DEFAULT_RULES_DIR = os.getenv(
    "YARA_RULES_DIR",
    os.path.join(os.path.dirname(__file__), "..", "..", "yara_rules"),
)


class YaraScanError(Exception):
    """Raised when YARA rules fail to compile or a scan cannot be completed."""


@dataclass
class YaraMatch:
    rule_name: str
    tags: List[str]
    matched_strings: List[str]


def load_rules(rules_dir: str = None) -> "yara.Rules":
    """
    Compile all .yar/.yara files in the given directory into a single ruleset.

    Raises YaraScanError if the directory has no rule files or compilation fails.
    """
    rules_dir = rules_dir or DEFAULT_RULES_DIR
    if not os.path.isdir(rules_dir):
        raise YaraScanError(f"YARA rules directory not found: {rules_dir}")

    rule_files = {}
    for fname in os.listdir(rules_dir):
        if fname.endswith((".yar", ".yara")):
            namespace = os.path.splitext(fname)[0]
            rule_files[namespace] = os.path.join(rules_dir, fname)

    if not rule_files:
        raise YaraScanError(f"No .yar/.yara rule files found in {rules_dir}")

    try:
        return yara.compile(filepaths=rule_files)
    except yara.Error as exc:
        raise YaraScanError(f"Failed to compile YARA rules: {exc}") from exc


def scan_data(rules: "yara.Rules", data: bytes) -> List[YaraMatch]:
    """
    Scan a blob of bytes against a compiled ruleset.

    Returns an empty list on no matches (TC-DT-03) -- never fabricates results.
    """
    try:
        raw_matches = rules.match(data=data)
    except yara.Error as exc:
        raise YaraScanError(f"YARA scan failed: {exc}") from exc

    results = []
    for m in raw_matches:
        matched_strings = []
        # yara-python >=4.3 exposes m.strings as a list of StringMatch objects
        for s in getattr(m, "strings", []):
            try:
                matched_strings.append(s.identifier)
            except AttributeError:
                matched_strings.append(str(s))
        results.append(YaraMatch(rule_name=m.rule, tags=list(m.tags), matched_strings=matched_strings))
    return results


def scan_file(rules: "yara.Rules", file_path: str) -> List[YaraMatch]:
    """Scan a file on disk against a compiled ruleset."""
    try:
        raw_matches = rules.match(filepath=file_path)
    except yara.Error as exc:
        raise YaraScanError(f"YARA scan failed for '{file_path}': {exc}") from exc

    results = []
    for m in raw_matches:
        matched_strings = [getattr(s, "identifier", str(s)) for s in getattr(m, "strings", [])]
        results.append(YaraMatch(rule_name=m.rule, tags=list(m.tags), matched_strings=matched_strings))
    return results


def build_combined_rules_file(rules_dir: str = None) -> Optional[str]:
    """
    Combine all .yar/.yara files in rules_dir into a single temp file,
    suitable for Volatility 3's --yara-file CLI option (which accepts only
    one file, not a directory) -- used by analysis.volatility_wrapper's
    live in-memory YARA scan via windows.vadyarascan/linux.vmayarascan.

    Validates the ACTUAL combined file compiles cleanly (as one flat
    namespace, exactly as Volatility will use it) before returning, so a
    syntax error OR a duplicate rule name across two different rule files
    is caught here with a clear message, rather than surfacing later as an
    opaque Volatility subprocess failure.

    (An earlier version of this function validated each rule file under
    its own per-file namespace before writing a plain concatenation --
    which let two files defining a same-named rule pass validation cleanly
    while the actual concatenated file, compiled as a single namespace,
    then failed at Volatility-run-time with "duplicated identifier". Fixed
    by validating the exact file that will actually be used.)

    Returns None if the rules directory doesn't exist or has no rule files
    -- this is not an error condition, since YARA scanning is optional and
    the caller can simply skip it. Raises YaraScanError if rules exist but
    fail to compile (including on a duplicate rule name across files).
    """
    rules_dir = rules_dir or DEFAULT_RULES_DIR
    if not os.path.isdir(rules_dir):
        return None

    rule_file_paths = [
        os.path.join(rules_dir, fname)
        for fname in sorted(os.listdir(rules_dir))
        if fname.endswith((".yar", ".yara"))
    ]
    if not rule_file_paths:
        return None

    combined_fd, combined_path = tempfile.mkstemp(suffix=".yar", prefix="combined_rules_")
    with os.fdopen(combined_fd, "w") as out_file:
        for path in rule_file_paths:
            with open(path, "r") as rule_file:
                out_file.write(f"// --- from {os.path.basename(path)} ---\n")
                out_file.write(rule_file.read())
                out_file.write("\n\n")

    try:
        yara.compile(filepath=combined_path)
    except yara.Error as exc:
        os.remove(combined_path)
        raise YaraScanError(
            f"Failed to compile combined YARA rules from {rules_dir}: {exc}. "
            "If this is a 'duplicated identifier' error, two different rule "
            "files define a rule with the same name -- rename one of them."
        ) from exc

    return combined_path
