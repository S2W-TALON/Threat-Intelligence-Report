rule CyberCrime_LockBit_LockBit5_Ransomware {
    meta:
        description = "Rule to detect LockBit 5.0 Ransomware"
        author = "gmrdkd@s2w.inc"
        created_at = "2025-12-18"
        version = "v1.0"

        threat_actor = "LockBit"
        category = "Malware"
        malware_name = "LockBit 5.0 Ransomware"
        severity = "High"

        hash1 = "f79ea684b3d459cf3f9d93dac0818ad5"

    strings:
        $check_country_code1 = { FF D0 [0-3] 3D 19 04 00 00 }
        $check_country_code2 = { FF D0 [0-3] 3D C9 00 00 00 }

        $API_resolve = {
            44 31 ??                 
            [0-1] 8D ?? ?? ?? 00 00       
            [0-1] 0F AF ??                
            [0-3] 01 ??                   
            [0-1] 89 ??                   
            [0-1] 81 ?? ?? ?? 00 00       
        }
        $encrypt_code1 = { 48 81 ?? 00 00 00 05 } 
        $encrypt_code2 = {                  
            48 8D ?? FF FF 7F 00          
            48 C1 ?? 14                     
            4? ?? F8 FF FF FF FF 07 00 00  
            4? 21 ??                        
            4? 8D ?? ??                   
            4? 83 ?? 60                    
        }
        $sha512_customIV_1 = { 10 C9 BD F2 67 E6 09 6A }
    condition:
        uint16(0) == 0x5A4D and
        all of them
}