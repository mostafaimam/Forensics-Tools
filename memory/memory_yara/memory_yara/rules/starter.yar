// A small starter ruleset for memory_yara. These are generic detection
// signatures (documented indicators, not exploit code) meant as a
// demonstration and a starting point - not a substitute for a
// maintained threat-intelligence feed.

rule Eicar_Test_String
{
    meta:
        description = "EICAR antivirus test string"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Mimikatz_Strings
{
    meta:
        description = "strings commonly present in Mimikatz or its modules"
        severity = "high"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "sekurlsa::pth" nocase
        $s3 = "Invoke-Mimikatz" nocase
        $s4 = "mimikatz(powershell)" nocase
        $s5 = { 6D 69 6D 69 6B 61 74 7A }  // "mimikatz" (hex form)
    condition:
        any of them
}

rule Encoded_PowerShell_Cradle
{
    meta:
        description = "encoded/download-cradle PowerShell command line"
        severity = "medium"
    strings:
        $enc1 = "-enc " nocase
        $enc2 = "-EncodedCommand" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "IEX(New-Object" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
    condition:
        1 of ($enc1, $enc2) or ($dl1 and $dl2) or $bypass
}

rule MSF_Stager_Prologue
{
    meta:
        description = "common Metasploit-style stager entry sequence"
        severity = "high"
    strings:
        $stager = { FC 48 83 E4 F0 }
    condition:
        $stager
}

rule Generic_Webshell_Eval
{
    meta:
        description = "a PHP eval() over a decoded/POSTed payload - a common webshell shape"
        severity = "medium"
    strings:
        $a = "eval(base64_decode(" nocase
        $b = "eval(gzinflate(" nocase
        $c = "assert($_POST[" nocase
        $d = "eval($_REQUEST[" nocase
    condition:
        any of them
}
