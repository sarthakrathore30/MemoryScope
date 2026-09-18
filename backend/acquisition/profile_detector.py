"""
OS profile detection for uploaded memory images (FR-3, TC-AC-04).

Shells out to the Volatility 3 CLI (`vol`) rather than the internal framework
API, since the CLI's automagic layer already handles the messy work of
trying Windows/Linux/Mac symbol tables and layer stacking.
"""
import json
import shutil
import subprocess

from acquisition.exceptions import ProfileDetectionError

VOL_TIMEOUT_SECONDS = 300  # profile probing should be quick relative to full analysis


def _run_vol_plugin(image_path: str, plugin: str) -> list:
    """Run a single Volatility3 plugin against an image and return parsed JSON rows."""
    vol_bin = shutil.which("vol")
    if not vol_bin:
        raise ProfileDetectionError("Volatility 3 CLI ('vol') not found on PATH.")

    cmd = [vol_bin, "-q", "-r", "json", "-f", image_path, plugin]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=VOL_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as exc:
        raise ProfileDetectionError(f"Profile detection timed out running {plugin}.") from exc

    if result.returncode != 0:
        raise ProfileDetectionError(
            f"Volatility plugin '{plugin}' failed: {result.stderr.strip()[:500]}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ProfileDetectionError(
            f"Could not parse Volatility output for '{plugin}': {exc}"
        ) from exc


def detect_os_profile(image_path: str) -> str:
    """
    Attempt to identify the OS profile of a memory image.

    Tries windows.info first (most common case for the sample images used in
    this project), then falls back to banners.Banners for Linux/generic
    banner-string detection.

    Returns a human-readable profile string (e.g. "Win10x64 (build 19041)")
    or "Unknown" if detection fails on both paths (does not raise, so
    acquisition can still proceed with status reflecting unknown profile).
    """
    # Attempt Windows detection.
    try:
        rows = _run_vol_plugin(image_path, "windows.info.Info")
        info = {row.get("Variable"): row.get("Value") for row in rows}
        kernel_version = info.get("Kernel Version") or info.get("NTBuildLab")
        is_64bit = info.get("Is64Bit")
        if kernel_version:
            arch = "x64" if is_64bit in (True, "True", "TRUE") else "x86"
            return f"Windows ({kernel_version}, {arch})"
    except ProfileDetectionError:
        pass

    # Attempt Linux/generic banner detection. Note: the plugin is registered
    # at the top level as "banners.Banners" (it lives at
    # volatility3/framework/plugins/banners.py, not under a linux/
    # subdirectory) -- "linux.banners.Banners" does not exist and always
    # fails, which silently broke Linux OS detection entirely until this fix.
    try:
        rows = _run_vol_plugin(image_path, "banners.Banners")
        if rows:
            banner = rows[0].get("Banner", "Linux (banner detected)")
            return f"Linux ({banner[:80]})"
    except ProfileDetectionError:
        pass

    return "Unknown"
