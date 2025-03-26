
rule Actor_APT_EarthEstries_MAL_WIN_EXE_Loader_Draculoader_Strings_Mar25 
{
    meta:
        rule_id = "e3edc8fd-50ff-4852-bc18-f5efd3b857e0"
        date = "23-03-2025"
        author = "RustyNoob619"
        description = "Detects the DLL Loader called DracuLoader used to execute the HemiGate Backdoor used by APT Earth Estries"
        source = "https://www.trendmicro.com/en_gb/research/23/h/earth-estries-targets-government-tech-for-cyberespionage.html"
        filehash = "169ca1b4c9ca3aef84ef2c5320c032b6ff87608edcbf9b74df3a195b27d31082"

    strings:
        $sample = "SAMPLE" wide fullword

        $str1 = "c:\\programdata\\WinDrive\\" wide fullword
        $str2 = "cmd /c c:\\programdata\\WinDrive\\taskhask.exe" ascii fullword
        $str3 = "\\syswow64\\" ascii fullword
        $str4 = "Key:cd\\" ascii fullword
        $str5 = "sc query powermgrenhance" ascii fullword
        $str6 = "net view /domain" ascii fullword 
        $str7 = "ping dfadcv2" ascii fullword
        $str8 = "dir c:\\windows\\syswow64\\powermgren" ascii fullword
        $str9 = "net user dfamis 1qaz@WSX /add" ascii fullword
        $str10 = "net localgroup administrators dfamis /add" ascii fullword
    
    condition: 
        uint16(0) == 0x5a4d
        and $sample
        and 7 of ($str*)
        and filesize < 1MB 
}

