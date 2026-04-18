
rule Actor_APT_DPRK_LABYRINTH_CHOLLIMA_MAL_WIN_PE_Implant_Dozer_Strings_Mar26
{
    meta:
        rule_id = "efdd22f7-ced9-4004-bd8b-cf7ddd5bd445"
        date = "25-03-2026"
        author = "Rustynoob619"
        description = "Detects Dozer malware used by DPRK APT LABYRINTH CHOLLIMA based on observed strings"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "7dee2bd4e317d12c9a2923d0531526822cfd37eabfd7aecc74258bb4f2d3a643"

    strings:
        $str1 = "HTTP/1.1 GET /china/dns" ascii fullword
        $str2 = "_MUTEX_AHN_V3PRO_" ascii fullword
        $str3 = "vmware.bat" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and 2 of them
        and filesize < 750KB

}
