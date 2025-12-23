rule CyberCrime_DragonForce_Ransomware
{
    meta:
        description = "Detection rule for DragonForce"
        author = "yeol@s2w.inc"
        created_at = "2025-12-23"
        version = "v1.0"
        threat_actor = "DragonForce"
        category = "malware"
        malware_name = "DragonForce Ransomware"
        severity = "Low"
        hash1 = "ada4e228e982a7e309bb6a3308e4872d"

    strings:
        $decrypt_str = {
            8A [4-6]
            B9 ?? ?? ?? ??
            0F B6 C0
            2B ??
        }
        $decrypt_str2 = {
            99
            F7 FF
            8D 42 7F
            99
            F7 FF
            88 54 34 19
            46
            83 ?? ??
            72 ??
        }
        $decrypt_str3 = {
            0F B6 ?? 1C E9 00 00 00
            [6-10]
            89 C8
            F7 EE
            89 C8
            C1 F8 1F
            01 CA
            C1 FA ??
            29 C2
            89 D0
        }
        $decrypt_str4 = {
            C1 ?? ??
            29 C2
            89 D0
            C1 E0 ??
            29 D0
            29 C1
            88 8C ?? E9 00 00 00
            83 C3 ??
            83 FB ??
        }
        $log_str1 = "Process is elevated: %d" ascii wide nocase
        $log_str2 = "Running under: %s" ascii wide nocase
        $chacha_str = "expand 32-byte k" ascii wide nocase
        $wsa_extend_fnc_hash1 = { B9 07 A2 25 } 
        $wsa_extend_fnc_hash2 = { F3 DD 60 46 }
        $wsa_extend_fnc_hash3 = { 8E E9 76 E5 }
        $wsa_extend_fnc_hash4 = { 8C 74 06 3E }


    condition:
        ((uint16(0) == 0x5A4D))
        and (
            ($decrypt_str and $decrypt_str2) or
            ($decrypt_str3 and $decrypt_str4)
        )
        and $log_str1
        and $log_str2
        and $chacha_str
        and (
            $wsa_extend_fnc_hash1
            or $wsa_extend_fnc_hash2
            or $wsa_extend_fnc_hash3
            or $wsa_extend_fnc_hash4
        )
}
