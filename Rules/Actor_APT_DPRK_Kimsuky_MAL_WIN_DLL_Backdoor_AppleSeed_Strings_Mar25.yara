
rule Actor_APT_DPRK_Kimsuky_MAL_WIN_DLL_Backdoor_AppleSeed_Strings_Mar25
{
    meta:
        rule_id = "1b35eb17-f103-4d40-86aa-521b4b2736d2"
        date = "25-03-2025"
        author = "RustyNoob619"
        description = "Detects Apple Seed DLL used by DPRK APT Kimsuky"
        source = "https://image.ahnlab.com/atip/content/atcp/2021/11/KIMSUKY-%EC%A1%B0%EC%A7%81%EC%9D%98-OP.Light-Shell.pdf"
        filehash = "d7711e0b96f18d5651418b7e3d5be9655dfe5da29e2d0536344c77532caf011a"

    strings:
        $pdb1 = "E:\\works\\utopia\\Utopia_v0.2\\bin\\AppleSeed64.pdb"
        $pdb2 = "E:\\works\\utopia\\Utopia_v0.2\\bin\\AppleSeed.pdb"

        $dll = "DllInstall" ascii fullword

        $apple1 = "AppleSeed64.dll" ascii fullword
        $apple2 = "AppleSeed.dll" ascii fullword

        $str1 = "m=uranos" ascii fullword
        $str2 = "%s\\conf.ini" ascii fullword
        $str3 = "cmd /c %s" ascii fullword
        $str4 = "win%d.%d.%d-sp%d-%s" ascii fullword
        $str5 = "%s.tmp" ascii fullword
        $str6 = "%s\\%s_%s" ascii fullword 

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 250KB 
        and $dll
        and ((any of ($pdb*) or any of ($apple*))
        or (5 of ($str*)))
}