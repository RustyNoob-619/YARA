rule Actor_APT_CN_UAT7290_MAL_ELF_Multiple_EncrptKeys_Jan26
{
    meta:
        rule_id = "7a9610f1-9990-43cd-9d3e-d7b571a4e3d1"
        date = "16-01-2026"
        author = "Rustynoob619"
        description = "Detects malware used by Chinese APT UAT-7290 based on AES keys used for encryption"
        source = "https://blog.xlab.qianxin.com/mystrodx_covert_dual-mode_backdoor_en/#mystrodx-backdoor-analysis"
        filehash = "3ce9ecfe196fd148dc49975eb33ff0923796718a"

    strings:
        $GCC = "GCC: (Buildroot 2015.02) 4.8.4" ascii fullword

        $key1 = {00 02 07 11 13 19 04 06 16 0E 18 0B 02 2D 0B 19 A0 91 02 23 96 45 6C 1C B1 D2 7F E3 22 00 00 00}

        $key2 = {02 06 03 09 04 02 0e 0a 01 0f 08 0a 04 0d 0b 09 0a 09 01 03 06 05 6d 0c 01 02 0f 03 03 0a 05 00}

    condition:
        uint32be(0) == 0x7f454c46
        and $GCC
        and any of ($key*)
        and filesize < 2MB

}
