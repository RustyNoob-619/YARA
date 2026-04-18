rule Actor_APT_DPRK_Lazarus_MAL_WIN_PY_Backdoor_TSUNAMI_Strings_Feb26
{
    meta:
        rule_id = "9ae2b2f7-3827-4f3f-8e85-47cbb85eab15"
        date = "14-02-2026"
        author = "Rustynoob619"
        description = "Detects TSUNAMI Python backdoor used by DPRK APT Lazarus based on strings"
        source = "https://redasgard.com/blog/hunting-lazarus-contagious-interview-c2-infrastructure"
        filehash = "ed882192a8870f5c45346dede856d1314fa0d989695f105a6a06f26e40c2ff1b"

    strings:
        $imports = "import" ascii

        $tsu1 = "Tsunami Payload" ascii fullword
        $tsu2 = "Tsunami Installer" ascii fullword
        $tsu3 = "Tsunami Client" ascii fullword
        $tsu4 = "TSUNAMI_INJECTOR" ascii
        $tsu5 = "TSUNAMI_PAYLOAD" ascii
        $tsu6 = "TSUNAMI_INSTALLER" ascii
        
        $str1 = "powershell.exe" ascii
        $str2 = "Runtime Broker" ascii
        $str3 = "Windows Update Script.pyw" ascii
        $str4 = "HappyPenguin1950" ascii

    condition:
        #imports > 10
        and any of ($tsu*)
        and any of ($str*)
        and filesize < 250KB 

}
