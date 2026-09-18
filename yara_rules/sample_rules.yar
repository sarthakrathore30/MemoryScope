/*
    Sample YARA rules for the Memory Forensics Platform.

    These are illustrative, low-risk pattern rules meant for demonstrating
    the detection pipeline end-to-end (TC-DT-02, TC-DT-03) and for academic
    evaluation. Administrators can add/update rules in this directory
    without any source code changes (FR-14).
*/

rule Suspicious_Mimikatz_Strings
{
    meta:
        description = "Detects common Mimikatz-related string artifacts in process memory"
        author = "Memory Forensics Platform"
        severity = "high"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide
        $s2 = "mimikatz" ascii wide nocase
        $s3 = "gentilkiwi" ascii wide nocase
    condition:
        any of them
}

rule Suspicious_PowerShell_Encoded_Command
{
    meta:
        description = "Detects base64-encoded PowerShell command-line invocation patterns"
        author = "Memory Forensics Platform"
        severity = "medium"
    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $bypass = "-ExecutionPolicy Bypass" ascii wide nocase
    condition:
        any of them
}

rule Suspicious_Reflective_DLL_Loader
{
    meta:
        description = "Detects common reflective DLL injection loader markers"
        author = "Memory Forensics Platform"
        severity = "high"
    strings:
        $marker1 = "ReflectiveLoader" ascii wide
        $marker2 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 } // MZ header pattern in unexpected memory region
    condition:
        any of them
}
