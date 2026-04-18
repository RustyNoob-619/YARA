rule Actor_APT_DPRK_GOLDEN_CHOLLIMA_MAL_WIN_PE_Implant_Jeus_Strings_Apr26
{
    meta:
        rule_id = "74873ea7-ac6e-487f-8101-4186fac4aa24"
        date = "02-04-2026"
        author = "Rustynoob619"
        description = "Detects Jeus malware used by DPRK APT GOLDEN CHOLLIMA based on observed strings"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "fe948451df90df80c8028b969bf89ecbf501401e7879805667c134080976ce2e"
    
    strings:
        $wide1 = "bloxholder.com" wide fullword
        $wide2 = "daemon/update.php" wide fullword
        $wide3 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36" wide
        
        $str1 = "act=check" ascii fullword
        $str2 = "Windows %d(%d)-%s" ascii fullword
        $str3 = "Gd2n5frvG2eZ1KOe" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and any of ($wide*)
        and 2 of ($str*)
        and filesize < 500KB
}
