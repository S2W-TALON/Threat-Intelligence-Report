rule APT_RedMehshen_BPFDoor_Malware_TARGET 
{
    meta:
        description = "Yara rule for detecting BPFDoor using  MD5 Salt"
        author = "gimjiho@s2w.inc"
        created_at = "2025-04-28"
        version = "v1.0"
        threat_actor = "Red Menshen"
        category = "Malware"
        malware_name = "BPFDoor"
        severity = "High"
        tlp = "TLP_WHITE"
        hash1 = "a47d96ffe446a431a46a3ea3d1ab4d6e"
        hash2 = "227fa46cf2a4517aa1870a011c79eb54"

    strings:
        $cert1 = "MIIB+zCCAWQCCQCtA0agZ+qO5jANBgkqhkiG9w0BAQsFADBCMQ" ascii
        $cert2 = "MIIB+zCCAWQCCQCRWTCAgNw5uDANBgkqhkiG9w0BAQsFADBCMQ" ascii
        $cert3 = "MIIB+zCCAWQCCQCqP/hy9MbncDANBgkqhkiG9w0BAQUFADBCMQ" ascii

        $rsa_private1 = "MIICXAIBAAKBgQDHUm876eqvbiDBzxq3rHU21m3sOgOLX8Z78X" ascii
        $rsa_private2 = "MIICXQIBAAKBgQDfueg7/eVgCd8iq0ysDXtiJhPZNw8uFZ9jmX" ascii
        $rsa_private3 = "MIICXAIBAAKBgQCyzeYCrtefDOtpsfZJ9Op8Bz3fPlprTjz8UM" ascii

        $md5_salt = {C6 45 ?? 49 C6 45 ?? 35 C6 45 ?? 2A C6 45 ?? 41 C6 45 ?? 59 C6 45 ?? 62 C6 45 ?? 73 C6 45 ?? 40 C6 45 ?? 4C C6 45 ?? 64 C6 45 ?? 61 C6 45 ?? 57 C6 45 ?? 62 C6 45 ?? 73 C6 45 ?? 4F}

        $bpf_magic1 = {?? 00 00 ?? 93 52 00 00}
        $bpf_magic2 = {?? 00 ?? ?? 55 72 00 00}
	
    condition:
        uint32(0) == 0x464C457F
        and ((any of ($cert*)) or (any of ($rsa_private*)))
        and $md5_salt 
        and (any of ($bpf_magic*))
}

rule APT_BPFDoor_Malware_BULK
{
    meta:
        description = "Yara rule for detecting BPFDoor"
        author = "gimjiho@s2w.inc"
        created_at = "2025-04-28"
        version = "v1.0"
        threat_actor = "n/a"
        category = "Malware"
        malware_name = "BPFDoor"
        severity = "Low"
        tlp = "TLP_WHITE"
        hash1 = "3a2a08c0f98389d8def6fe82fcb3cc1b"
        hash2 = "d5fb6d880ac18de3494d7cbb943935b9"

    strings:
        $bpf_magic1 = {48 00 00 00 ?? 00 00 00 15 00 [2] 93 52}
        $bpf_magic2 = {48 00 00 00 ?? 00 00 00 15 00 [2] 55 72}
        $bpf_magic3 = {48 00 00 00 00 00 00 00 02 00 00 00 0? 00 00 00 00 00 00 00 93 52}
        $bpf_magic4 = {48 00 00 00 00 00 00 00 02 00 00 00 0? 00 00 00 00 00 00 00 55 72}
        $bpf_magic5 = {C? 85 [4] 15 00 C? 85 [4] 13 C? 85 [4] 14 C7 85 [4] 55 72}
        $bpf_magic6 = { 3D 9F CD 30 44 }          // cmp eax, 0x4430CD9F
        $bpf_magic7 = { 81 ?? 66 27 14 5E }       // cmp reg32, 0x5E142766	

        $bpf_open1 = {33 34 35 38}
        $bpf_open2 = {C6 [0-5] 4D C6 [0-5] 59 C6 [0-5] 53 C6 [0-5] 51 C6 [0-5] 4C C6 [0-5] 5F C6 [0-5] 48 C6 [0-5] 49 C6 [0-5] 53 C6 [0-5] 54}
        $bpf_open3 = "kdmtmpflush" ascii wide
        $bpf_open4 = "ptem" ascii wide
        $bpf_open5 = "dterm" ascii wide
        $bpf_open6 = {
            (C6 85 [4] 71)
            (C6 85 [4] 6D)
            (C6 85 [4] 67)
            (C6 85 [4] 72) 
            (C6 85 [4] 20) 
            (C6 85 [4] 2D)
            (C6 85 [4] 6C)
            (C6 85 [4] 20) 
            (C6 85 [4] 2D)
            (C6 85 [4] 74)
            (C6 85 [4] 20)
            (C6 85 [4] 66)
            (C6 85 [4] 69) 
            (C6 85 [4] 66)
            (C6 85 [4] 66) 
            (C6 85 [4] 6F) 
            (C6 85 [4] 20) 
            (C6 85 [4] 2D)
            (C6 85 [4] 75) 
        } // qmgr -l -t fifo -u

    condition:
        uint32(0) == 0x464C457F
        and (any of ($bpf_magic*))
        and (4 of ($bpf_open*))
}

rule APT_RedMehshen_BPFDoorController_Malware
{
    meta:
        description = "Yara rule for detecting BPFDoor Controller"
        author = "gimjiho@s2w.inc"
        created_at = "2025-04-28"
        version = "v1.0"
        threat_actor = "n/a"
        category = "Malware"
        malware_name = "BPFDoor Controller"
        severity = "Mid"
        tlp = "TLP_WHITE"
        hash1 = "a8c54d5b028714be5fdf363957ab8de2"
        hash2 = "8f05657f0bd8f4eb60fba59cc94fe189"

    strings:
        $opt = ":h:d:l:s:b" ascii wide
        $magic_seq1 = {C7 05 [4] 71 55}
        $magic_seq2 = {C7 05 [4] 72 55}
        $magic_seq3 = {C7 05 [4] 52 93}

        $dbg_str1 = "[+] listen on port" ascii wide
        $dbg_str2 = "[-] bind port failed." ascii wide
        $dbg_str3 = "[+] crypt" ascii wide
        $dbg_str4 = "Connection closed." ascii wide
        $dbg_str5 = "[+] Packet Successfuly Sending" ascii wide

    condition:
        uint32(0) == 0x464C457F
        and $opt
        and (2 of ($magic_seq*))
        and (2 of ($dbg_str*))
}

rule elf_bpfdoor_w3 {
    meta:
        description = "Detects BPFDoor, new 2023 variant"
        author = "Sorint.lab"
        creation_date = "2023-05-15"
        last_modified = "2023-05-15"
        reference_sample = "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7"
        severity = 100
        scan_context = "file, memory"
        os = "linux"
        notes = "https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bpfdoor"
        malpedia_version = "20230515"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        malpedia_rule_date = "20230515"
        malpedia_hash = ""
    strings:
        // BPF Code detected in the executable
        $op1 = { 28 00 00 00 0C 00 00 00 15 00 00 09 DD 86 00 00 }
        $op2 = { 15 00 11 10 BB 01 00 00 15 00 00 11 00 08 00 00 }
        // Magic number 0x4430CD9F
        $op3 = { 9F CD 30 44 }
    condition:
        uint16(0) == 0x457f and all of them
}

rule elf_bpfdoor_w2 {
    meta:
        description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
        author = "Florian Roth"
        reference = "https://twitter.com/jcksnsec/status/1522163033585467393"
        date = "2022-05-08"
        score = 85
        hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
        hash2 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
        version = "1"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bpfdoor"
        malpedia_rule_date = "20220509"
        malpedia_hash = ""
        malpedia_version = "20220509"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $s2 = "/sbin/mingetty /dev" ascii fullword
        $s3 = "pickup -l -t fifo -u" ascii fullword
    condition:
        uint16(0) == 0x457f and
        filesize < 200KB and 2 of them or all of them
}

rule elf_bpfdoor_w1 {
    meta:
        description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
        author = "Florian Roth"
        reference = "https://twitter.com/jcksnsec/status/1522163033585467393"
        date = "2022-05-07"
        score = 85
        hash1 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
        hash2 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
        hash3 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
        hash4 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
        version = "1"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bpfdoor"
        malpedia_rule_date = "20220509"
        malpedia_hash = ""
        malpedia_version = "20220509"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $opx1 = { 48 83 c0 0c 48 8b 95 e8 fe ff ff 48 83 c2 0c 8b 0a 8b 55 f0 01 ca 89 10 c9 }
        $opx2 = { 48 01 45 e0 83 45 f4 01 8b 45 f4 3b 45 dc 7c cd c7 45 f4 00 00 00 00 eb 2? 48 8b 05 ?? ?? 20 00 }

        $op1 = { 48 8d 14 c5 00 00 00 00 48 8b 45 d0 48 01 d0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 83 c0 01 48 01 45 e0 }
        $op2 = { 89 c2 8b 85 fc fe ff ff 01 c2 8b 45 f4 01 d0 2d 7b cf 10 2b 89 45 f4 c1 4d f4 10 }
        $op3 = { e8 ?? d? ff ff 8b 45 f0 eb 12 8b 85 3c ff ff ff 89 c7 e8 ?? d? ff ff b8 ff ff ff ff c9 }
    condition:
        uint16(0) == 0x457f and
        filesize < 100KB and 2 of ($opx*) or 4 of them
}

rule elf_bpfdoor_w0 {
    meta:
        description = "Detects unknown Linux implants (uploads from KR and MO)"
        author = "Florian Roth"
        reference = "https://twitter.com/jcksnsec/status/1522163033585467393"
        date = "2022-05-05"
        score = 90
        hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
        hash2 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
        hash3 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
        hash4 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
        hash5 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
        hash6 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
        hash7 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
        hash8 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
        hash9 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
        hash10 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
        version = "1"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bpfdoor"
        malpedia_rule_date = "20220509"
        malpedia_hash = ""
        malpedia_version = "20220509"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "[-] Connect failed." ascii fullword
        $s2 = "export MYSQL_HISTFILE=" ascii fullword
        $s3 = "udpcmd" ascii fullword
        $s4 = "getshell" ascii fullword

        $op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 }
        $op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? }
        $op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 }
        $op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee }
    condition:
        uint16(0) == 0x457f and
        filesize < 80KB and 2 of them or 5 of them
}
