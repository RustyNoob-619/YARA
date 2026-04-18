import "lnk"

rule Actor_APT_IN_MysteriousElephant_MAL_WIN_LNK_Artifacts_1_Mar26
{
    meta:
        rule_id = "4cd808bf-ce97-40d0-92ae-6449a84e86b0"
        date = "20-03-2026"
        author = "Rustynoob619"
        description = "Detects LNK files used by Indian APT Mysterious Elephant based on commmand line arguements"
        source = "https://securelist.com/mysterious-elephant-apt-ttps-and-tools/117596/"
        filehash = "ddc8afb9f1b9143e036c7044fdfd8aa639093f5b788696e3344b386bb6d5dad2"

    condition:
        uint32be(0) == 0x4c000000
        and (
            lnk.cmd_line_args startswith "/c for /f \"delims=\" %F in ('where /r %Temp%"
            )
        and filesize < 50KB

}
