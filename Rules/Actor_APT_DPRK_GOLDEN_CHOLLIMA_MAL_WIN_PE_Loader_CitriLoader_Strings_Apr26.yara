rule Actor_APT_DPRK_GOLDEN_CHOLLIMA_MAL_WIN_PE_Loader_CitriLoader_Strings_Apr26
{
    meta:
        rule_id = "0ae5b44e-96b2-48a0-8234-e40e42f2d980"
        date = "06-04-2026"
        author = "Rustynoob619"
        description = "Detects a loader called CitriLoader used by DPRK APT GOLDEN CHOLLIMA based on observed strings"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "d0cf9c1f87eac9b8879684a041dd6a2e1a0c15e185d4814a51adda19f9399a9b"
    
    strings:
        $str1 = "FESAfaSDage" ascii
        $str2 = "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36" ascii
        $str3 = "0.9, image / avif, image / webp, image / apng, */*" ascii
        $str4 = "0.8,application/signed-exchange" ascii
        $str5 = "sec-ch-ua-mobile:" ascii
        $str6 = "%s%s%s%s = %s%s%s%s" ascii
        $str7 = "https://%s/%s%s%s" ascii 


    condition:
        uint16(0) == 0x5a4d
        and 4 of them
        and filesize < 500KB
}
