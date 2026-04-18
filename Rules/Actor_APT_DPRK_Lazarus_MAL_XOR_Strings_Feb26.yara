rule Actor_APT_DPRK_Lazarus_MAL_XOR_Strings_Feb26
{
    meta:
        rule_id = "9ae2b2f7-3827-4f3f-8e85-47cbb85eab15"
        date = "15-02-2026"
        author = "Rustynoob619"
        description = "Detects malware used by DPRK APT Lazarus based on XOR key strings"
        source = "https://redasgard.com/blog/hunting-lazarus-contagious-interview-c2-infrastructure"
        filehash = "ed882192a8870f5c45346dede856d1314fa0d989695f105a6a06f26e40c2ff1b"

    strings:
        $imports = "import" ascii
        $const = "const" ascii

        $xor1 = "G01d*8@(" ascii wide
        $xor1 = "G0Md*8@(" ascii wide
        $xor1 = "Vw1aGYoP" ascii wide
        $xor1 = "!!!HappyPenguin1950!!!" ascii wide
        $xor1 = "Xt3rqfmL" ascii wide
        $xor1 = "Ze4pq4iT" ascii wide

    condition:
        (#imports > 10 or #const > 10)
        and any of ($xor*) 
        and filesize < 250KB 

}
