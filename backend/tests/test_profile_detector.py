"""
Unit tests for acquisition/profile_detector.py.

This module previously had ZERO direct test coverage -- every existing test
either mocked detect_os_profile() away entirely at the API layer, or
monkeypatched analysis.volatility_wrapper._detect_os_family() to just
return "windows" directly. That gap is exactly how a real bug (calling the
nonexistent plugin "linux.banners.Banners" instead of the actual registered
"banners.Banners") went undetected: Linux OS detection silently failed on
every single Linux memory image, always falling through to "Unknown".
"""
import json
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from acquisition import profile_detector as pd


def _mock_completed_process(stdout_obj, returncode=0):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = json.dumps(stdout_obj)
    proc.stderr = ""
    return proc


@patch("acquisition.profile_detector.shutil.which", return_value="/usr/bin/vol")
@patch("acquisition.profile_detector.subprocess.run")
def test_detect_os_profile_windows_success(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([
        {"Variable": "Kernel Base", "Value": "0x804d7000"},
        {"Variable": "NTBuildLab", "Value": "2600.xpsp.080413-2111"},
        {"Variable": "Is64Bit", "Value": False},
    ])

    profile = pd.detect_os_profile("fake.raw")

    assert profile == "Windows (2600.xpsp.080413-2111, x86)"
    called_cmd = mock_run.call_args[0][0]
    assert "windows.info.Info" in called_cmd


@patch("acquisition.profile_detector.shutil.which", return_value="/usr/bin/vol")
@patch("acquisition.profile_detector.subprocess.run")
def test_detect_os_profile_linux_uses_correct_plugin_name(mock_run, mock_which):
    """
    Regression test for the real bug: the plugin is registered as the
    top-level "banners.Banners" (it lives at
    volatility3/framework/plugins/banners.py, not under linux/) --
    "linux.banners.Banners" does not exist and always fails.
    """
    call_log = []

    def fake_run(cmd, **kwargs):
        call_log.append(cmd)
        plugin = cmd[-1]
        if plugin == "windows.info.Info":
            return _mock_completed_process([], returncode=1)  # not Windows
        if plugin == "banners.Banners":
            return _mock_completed_process([
                {"Offset": 4096, "Banner": "Linux version 5.4.0-42-generic"},
            ])
        return _mock_completed_process([], returncode=1)

    mock_run.side_effect = fake_run

    profile = pd.detect_os_profile("fake.raw")

    assert profile.startswith("Linux")
    assert "Linux version 5.4.0-42-generic" in profile

    called_plugins = [cmd[-1] for cmd in call_log]
    assert "banners.Banners" in called_plugins
    assert "linux.banners.Banners" not in called_plugins


@patch("acquisition.profile_detector.shutil.which", return_value="/usr/bin/vol")
@patch("acquisition.profile_detector.subprocess.run")
def test_detect_os_profile_both_fail_returns_unknown(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([], returncode=1)

    profile = pd.detect_os_profile("fake.raw")

    assert profile == "Unknown"


@patch("acquisition.profile_detector.shutil.which", return_value=None)
def test_detect_os_profile_missing_vol_binary_returns_unknown_not_raise(mock_which):
    """detect_os_profile must never raise -- acquisition should still
    succeed with an unknown profile rather than failing the upload."""
    profile = pd.detect_os_profile("fake.raw")
    assert profile == "Unknown"
