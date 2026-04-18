rule SUS_WIN_LNK_Loader_Unknown_Strings_Feb26
{
    meta:
        rule_id = "4e8fddd3-6a17-4fc0-b1da-fd90e5b4912b"
        date = "25-02-2026"
        author = "Rustynoob619"
        description = "Detects suspicious LNK files using Conhost to execute download commands via curl based on observed command line arguements"
        filehash = "fa3a1153018ac1e1a35a65e445a2bad33eac582c225cf6c38d0886802481cd43"

    condition:
        uint32be(0) == 0x4c000000 
        and (
            lnk.cmd_line_args contains "shell32.dll"
            and lnk.cmd_line_args contains "ShellExec_RunDLL"
            and lnk.cmd_line_args contains "conhost"
            and lnk.cmd_line_args contains "--headless"
            and lnk.cmd_line_args contains "cmd /c"
            and lnk.cmd_line_args contains "curl"
            )
        and filesize < 25KB

}
