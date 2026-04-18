rule Actor_APT_CN_MustangPanda_MAL_WIN_PE_Backdoor_ToneShell_Feb26
{
    meta:
        rule_id = "8c93993e-2b8b-40d4-bc40-891a2d507ebc"
        date = "13-02-2026" 
        author = "Rustynoob619"
        description = "Detects Tone Shell backdoor used by Chinese APT Mustang Panda based on observed characteristics from the report"
        source = "https://securelist.com/honeymyte-kernel-mode-rootkit/118590/"
        filehash = "unknown"

    strings:
        $str1 = "CoCreateGuid" ascii wide
        $str2 = "C:\\ProgramData\\MicrosoftOneDrive.tlb" ascii wide
        $str3 = "SeLocalSystemSid" ascii wide

    condition:
        uint16(0) == 0x5a4d
        and 2 of them
}
