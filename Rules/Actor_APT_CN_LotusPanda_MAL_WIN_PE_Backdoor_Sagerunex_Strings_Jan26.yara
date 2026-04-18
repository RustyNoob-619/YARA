
rule Actor_APT_CN_LotusPanda_MAL_WIN_PE_Backdoor_Sagerunex_Strings_Jan26
{
    meta:
        rule_id = "ce7cd8e1-18df-41ca-a4d8-3f90ae349099"
        date = "20-01-2026"
        author = "Rustynoob619"
        description = "Detects Sagerunex Backdoor used by Chinese APT Lotus Panda based on strings"
        source = "https://securite360.net/the-intriguing-lotus-a-deep-dive-into-sagerunex"
        filehash = "5a3dd5bbd81057a77f625fc35ecd918cd8a193af9490a844303c4c3a06e6d24b"

    strings:
        $pth1 = "\\Microsoft" ascii fullword
        $pth2 = "\\Protect" ascii fullword
        $pth3 = "\\Windows\\" ascii fullword
  
        $str1 = "DMI%X.DAT" ascii fullword
        $str2 = "runexe" ascii fullword
        $str3 = "\\cmd.exe" ascii fullword
        $str4 = "0x00, %02d-%02d." ascii fullword

        $rgsr1 = "S-1-5-21" wide fullword
        $rgsr2 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" wide fullword
        $rgsr3 = "ProxyEnable" wide fullword
        $rgsr4 = "ProxyServer" wide fullword    

        $try1 = "0x01, try httpsviaconfigproxy." wide fullword 
        $try2 = "0x01, try httpswpadproxy." wide fullword  
        $try3 = "0x01, try httpsviaiexproxy." wide fullword 
        $try4 = "0x01, try httpsviafirefoxproxy." wide fullword  
        $try5 = "0x01, try httpsviaautoproxy." wide fullword  
        $try6 = "0x01, try httpspreconfig." wide fullword        

    condition:
        uint16(0) == 0x5a4d
        and all of ($pth*)
        and 3 of ($str*)
        and all of ($rgsr*)
        and 3 of ($try*)
        and filesize < 500KB 

}
