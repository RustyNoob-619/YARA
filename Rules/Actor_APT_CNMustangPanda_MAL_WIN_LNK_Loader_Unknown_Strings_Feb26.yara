import "lnk"

rule Actor_APT_CNMustangPanda_MAL_WIN_LNK_Loader_Unknown_Strings_Feb26
{
    meta:
        rule_id = "a90e0143-4be6-4266-b1bf-04ac8b865d85"
        date = "24-02-2026"
        author = "Rustynoob619"
        description = "Detects LNK files used by Chinese APT Mustang Panda based on command line obfuscation strings"
        source = "https://www.zscaler.com/blogs/security-research/china-nexus-threat-actor-targets-persian-gulf-region-plugx"
        filehash = "fa3a1153018ac1e1a35a65e445a2bad33eac582c225cf6c38d0886802481cd43"

    condition:
        uint32be(0) == 0x4c000000 
        and (
            lnk.cmd_line_args contains "-L\"\"skontv"
            or lnk.cmd_line_args contains "-d\"\"ecompile^"
            or lnk.cmd_line_args contains "0.ln\"\"k"
            )
        and filesize < 5KB

}
