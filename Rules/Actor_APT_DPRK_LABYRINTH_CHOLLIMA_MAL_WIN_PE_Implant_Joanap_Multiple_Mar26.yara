import "pe"

rule Actor_APT_DPRK_LABYRINTH_CHOLLIMA_MAL_WIN_PE_Implant_Joanap_Multiple_Mar26
{
    meta:
        rule_id = "e6dbd6e1-8603-4cc2-be36-50ba3816c92a"
        date = "27-03-2026"
        author = "Rustynoob619"
        description = "Detects Joanap malware used by DPRK APT LABYRINTH CHOLLIMA based on observed strings and Korean lang code"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "4fe3c853ab237005f7d62324535dd641e1e095d1615a416a9b39e042f136cf6b"

    strings:
        $spec1 = "9025jhdho39ehe2" ascii fullword
        $spec2 = "\\\\%s\\adnim$\\system32\\%s" ascii fullword

        $str1 = "cmd.exe /q /c net share adnim$ /delete" ascii
        $str2 = "cmd.exe /c %s %d.%d.%d.%d %d" ascii
        $str3 = "cmd.exe /q /c net share adnim$=%SystemRoot%" ascii
        $str4 = "password <=14" ascii
        $str5 = "Global\\FwtSqmSession106829323_S-1-5-19" ascii
       

    condition:
        uint16(0) == 0x5a4d
        and pe.locale(0x0412)
        and any of ($spec*)
        and 3 of ($str*) 
        and filesize < 750KB
}
