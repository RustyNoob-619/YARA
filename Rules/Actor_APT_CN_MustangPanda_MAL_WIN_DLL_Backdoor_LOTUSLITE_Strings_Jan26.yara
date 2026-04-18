
rule Actor_APT_CN_MustangPanda_MAL_WIN_DLL_Backdoor_LOTUSLITE_Strings_Jan26
{
    meta:
        rule_id = "acfa25c4-049e-40fd-a0c5-443a062ff9fd"
        date = "26-01-2026"
        author = "Rustynoob619"
        description = "Detects LOTUSLITE backdoor used by Chinese APT Mustang Panda based on strings"
        source = "https://www.acronis.com/en/tru/posts/lotuslite-targeted-espionage-leveraging-geopolitical-themes/"
        filehash = "2c34b47ee7d271326cfff9701377277b05ec4654753b31c89be622e80d225250"
    
    strings:
        $str1 = "I'm Chinese,haha." ascii fullword
        $str2 = "Ya nye rus-ski" ascii fullword
        $str3 = "session=GruNBA" wide fullword

        $pth1 = "Global\\Technology360-A@P@T-Team" ascii fullword
        $pth2 = "C:\\ProgramData\\Technology360NB" ascii fullword
        
        $hex = {BB AA 99 88}

    condition:
        uint16(0) == 0x5a4d
        and $hex
        and any of ($str*)
        and any of ($pth*)
        and filesize < 500KB
}
