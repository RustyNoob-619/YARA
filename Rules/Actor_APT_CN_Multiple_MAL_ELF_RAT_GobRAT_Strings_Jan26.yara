rule Actor_APT_CN_Multiple_MAL_ELF_RAT_GobRAT_Strings_Jan26
{
    meta:
        rule_id = "89f3cdcd-2540-4938-955f-a9db096c5544"
        date = "18-01-2026"
        author = "Rustynoob619"
        description = "Detects GobRAT malware used by Chinese APTs such as UAT-7290 and APT31 based on strings"
        source = "https://blogs.jpcert.or.jp/en/2023/05/gobrat.html"
        filehash = "Unknown :("

    strings:
        $str = "aaa.com/bbb/"
        $key = {050CFE3706380723433807193E03FE2F}

    condition:
        uint32be(0) == 0x7f454c46
        and (#str > 25 or $key)
        and filesize < 2MB
}
