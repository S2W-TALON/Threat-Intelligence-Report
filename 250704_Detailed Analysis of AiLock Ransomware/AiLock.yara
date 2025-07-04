rule CyberCrime_AiLock_AiLockRansomware {
    meta:
        description = "Detection rule for AiLock Ransomware"
        author = "gmrdkd@s2w.inc"
        created_at = "2025-04-03"
        version = "v1.0"
        reference = "-"

        threat_actor = "AiLock"
        category = "Malware"
        malware_name = "AiLock Ransomware"
        severity = "High"

        hash1 = "2a728d98ae8280efeaa674783181f3fa"

    strings:
        $string1 = ".AiLock" ascii wide nocase
        $string2 = "Start Log:%d Network:%d Selfdelete:%d Path=%s" ascii wide nocase
        $string3 = "Total time of encryption: %llu seconds" ascii wide nocase
        $string4 = "read=%u kbytes, write=%u kbytes, opened=%u, encPS=%u, totalFound=%u, TotalEncrypted=%u" ascii wide nocase
        $string5 = "Single instance only Exit" ascii wide nocase

        $marker1 = {BE BA AD AB}
        $marker2 = {B5 00 6B B1}
        $marker3 = {00 B5 B1 6B}
        $marker4 = {DE AD BA BE}
        $marker5 = {BA BE DE AD}

    condition:
        uint16(0) == 0x5A4D
        and all of ($marker*)
        and 2 of ($string*)
}
