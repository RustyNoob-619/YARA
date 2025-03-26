
import "pe"

rule Actor_APT_DPRK_Kimsuky_MAL_WIN_EXE_Backdoor_AppleSeed_Strings_Mar25
{
    meta:
        rule_id = "95907da8-6a49-4e82-b941-9d45c20799d1"
        date = "25-03-2025"
        author = "RustyNoob619"
        description = "Detects Apple Seed executable used by DPRK APT Kimsuky"
        source = "https://image.ahnlab.com/atip/content/atcp/2021/11/KIMSUKY-%EC%A1%B0%EC%A7%81%EC%9D%98-OP.Light-Shell.pdf"
        filehash = "6dfce07abc39e5d6aebd74a1850ad65cc6ce10a8540b551c4f6d441ec4cf48ab"

    strings:
        $str1 = "regsvr32.exe" ascii fullword
        $str2 = "del \"%s\"" ascii fullword
        $str3 = "%s\\rundll32.exe \"%s\",%s" ascii fullword
        $str4 = "notepad.exe" ascii fullword
        $str5 = "log.txt" ascii fullword
        $str6 = "cmd.txt" ascii fullword
        $str7 = "%s\\%s.dat" ascii fullword
        $str8 = "BINARY" ascii fullword

        $spec1 = "/data/cheditor/dir1" ascii fullword
        $spec2 = "/s /n /i NewACt.dat" ascii fullword
        $spec3 = ":\\Users\\ADMINI~1\\AppData\\Local\\Temp" wide

        $usragnt = "User-Agent: Mozilla/5.0 (Windows NT 6.1" ascii fullword

        $pdb = "E:\\pc\\makeHwp\\Bin\\makeHwp.pdb" ascii

    condition:
        (($pdb)
        or 
        (pe.locale(0x0412) //Korean Language Code
        and $usragnt
        and any of ($spec*)
        and 4 of ($str*)))
        and filesize < 500KB 
}
