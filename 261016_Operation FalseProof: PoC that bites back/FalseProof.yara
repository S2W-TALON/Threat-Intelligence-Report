rule CyberCrime_UNSI022_FalseProof_CoDawnloader
{
    meta:
        description = "Detection Rule for CoDawnloader payload from Operation FalseProof"
        author = "okas832@s2w.inc"
        created_at = "2026-03-26"
        version = "v1.0"
        threat_actor = "UNSI-022"
        category = "Malware"
        malware_name = "CoDawnloader"
        severity = "Mid"

    strings:
        $debug1 = "checkin update failed. Code:"
        $debug2 = "checkin update response:"
        $debug3 = "[+] Binary data downloaded. Size:"
        $debug4 = "[+] data link:"
        $c2 = "https://coda.io/apis/v1/docs"

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        all of ($debug*) and
        #c2 >= 2
}

rule CyberCrime_UNSI022_FalseProof_cryptography
{
    meta:
        description = "Detection Rule for a Malicious Linux Package (cryptography)"
        author = "gimjiho@s2w.inc"
        created_at = "2026-03-26"
        version = "v1.0"
        threat_actor = "UNSI-022"
        category = "Malware"
        malware_name = "FalseProof"
        severity = "Mid"

    strings:
        $str1 = "version_info" ascii
        $str2 = "/tmp/" ascii
        $str3 = "/site-packages/" ascii
        $str4 = "__file__" ascii

        $hash_logic = {
            E8 ?? ?? ?? ??
            41 0F BE 3?
            49 83 C? 01
            89 C0
            49 0F AF C?
            48 01 C0
            49 31 C?
            49 83 C? 01
            40 84 ??
            75 ??
        }

    condition:
        uint16(0) == 0x457F and
        3 of ($str*) and
        $hash_logic
}

rule CyberCrime_UNSI022_FalseProof_cryptography_pyd
{
    meta:
        description = "Detection Rule for a Malicious Windows Package (cryptography)"
        author = "gimjiho@s2w.inc"
        created_at = "2026-03-26"
        version = "v1.0"
        threat_actor = "UNSI-022"
        category = "Malware"
        malware_name = "FalseProof"
        severity = "Mid"

    strings:
        $sig1 = "\\site-packages\\"
        $sig2 = {
            49 8B D7
            4D 85 C0
            74 ??
            8D 42 01
            30 04 0A
            48 FF C2
            49 3B D0
            72 ??
        }
        $hash_logic1 = {
            E8 ?? ?? ?? ??
            0F B7 0E
            48 8D 76 02
            0F AF C3
            03 C0
            33 D8
            FF C3
        }
        $hash_logic2 = {
            E8 ?? ?? ?? ??
            ?? ?? ?? ??
            03 C0
            ?? ?? ??
            0F BE ?? ??
            ?? ?? ??
            ?? ?? ??
            85 C0
        }

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        all of ($hash_logic*) and
        any of ($sig*)
}
