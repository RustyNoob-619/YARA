rule Actor_APT_CN_UAT7290_MAL_ELF_Backdoor_SilentRaid_Strings_Jan26
{
    meta:
        rule_id = "238c17ea-5098-452e-9be2-5c5623ddb69d"
        date = "15-01-2026"
        author = "Rustynoob619"
        description = "Detects SilentRaid (aka MystRodX) malware used by Chinese APT UAT-7290 based on strings"
        source = "https://blog.talosintelligence.com/uat-7290/"
        filehash = "961ac6942c41c959be471bd7eea6e708f3222a8a607b51d59063d5c58c54a38d"

    strings:
        $GCC = "GCC: (Buildroot 2015.02) 4.8.4" ascii fullword

        $plug1 = "my_socks_mgr" ascii
        $plug2 = "my_rsh" ascii
        $plug3 = "port_fwd_mgr" ascii

        $str1 = "/etc/passwd" ascii
        $str2 = "8.8.8.8" ascii
        $str3 = "/bin/sh"

        $id1 = "id-at-dnQualifier" ascii
        $id2 = "id-at-pseudonym" ascii
        $id3 = "id-domainComponent" ascii
        $id4 = "id-at-uniqueIdentifier" ascii

    condition:
        uint32be(0) == 0x7f454c46
        and all of them
        and filesize < 2MB

}
