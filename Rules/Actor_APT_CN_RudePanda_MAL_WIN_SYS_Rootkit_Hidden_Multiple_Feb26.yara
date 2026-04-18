import "pe"

rule Actor_APT_CN_RudePanda_MAL_WIN_SYS_Rootkit_Hidden_Multiple_Feb26
{
    meta:
        rule_id = "feb4bdfe-e022-414d-862d-84263a0a757a"
        date = "08-02-2026" 
        author = "Rustynoob619"
        description = "Detects rootkit derived from the open-source Hidden project used by Chinese APT RudePanda based on PE properties and strings"
        source = "https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/"
        filehash = "f9dd0b57a5c133ca0c4cab3cca1ac8debdc4a798b452167a1e5af78653af00c1"

    strings:
        $hide = "hidden" ascii

        $str1 = "Winkbj" ascii
        $str2 = "[HahaDbg]" ascii
        $str3 = "Kbj_WinkbjFsDirs" wide fullword
        $str4 = "Kbj_WinkbjFsFiles" wide fullword
        $str5 = "Kbj_WinkbjRegKeys" wide fullword
        $str6 = "Kbj_WinkbjRegValues" wide fullword
        $str7 = "Kbj_WinkbjImages" wide fullword

    condition:
        uint16(0) == 0x5a4d
        and pe.imports("FLTMGR.SYS","FltRegisterFilter")
        and pe.imports("ntoskrnl.exe","ExAcquireFastMutex")
        and pe.imports("ntoskrnl.exe","CmRegisterCallbackEx")
        and #hide > 25
        and 6 of them
        and filesize < 1MB
}
