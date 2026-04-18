rule Actor_APT_DPRK_LABYRINTH_CHOLLIMA_MAL_WIN_PE_Implant_Brambul_Strings_Mar26
{
    meta:
        rule_id = "6f25d325-78fd-48de-83cf-38efd625323b"
        date = "26-03-2026"
        author = "Rustynoob619"
        description = "Detects Brambul malware used by DPRK APT LABYRINTH CHOLLIMA based on observed strings"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "d2359630e84f59984ac7ddebdece9313f0c05f4a1e7db90abadfd86047c12dd6"

    strings:
        $spec1 = "misssleepy0611@gmail.com" ascii fullword
        $spec2 = "9025jhdho39ehe2" ascii fullword
        $spec3 = "\\\\%s\\adnim$\\%s" ascii fullword

        $str1 = "cmd.exe /q /c net share adnim$ /delete" ascii
        $str2 = "cmd.exe /c %s" ascii
        $str3 = "cmd.exe /q /c net share adnim$=%SystemRoot%" ascii
        $str4 = "password <=14" ascii
       

    condition:
        uint16(0) == 0x5a4d
        and 2 of ($spec*)
        and 2 of ($str*)
        and filesize < 750KB

}
