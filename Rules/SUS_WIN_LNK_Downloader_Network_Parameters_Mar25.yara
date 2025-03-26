
import "lnk"

rule SUS_WIN_LNK_Downloader_Network_Parameters_Mar25
{
    meta:
        rule_id = "a2b53af1-46dd-4747-9726-6bc9883d9ffb"
        date = "19-03-2025"
        author = "RustyNoob619"
        description = "Detects suspicious LNK files attempting to download or contact C2 URLs"
        source = "https://x.com/0xmh1/status/1904496290630877424"
        filehash = "a66c25b1f0dea6e06a4c9f8c5f6ebba0f6c21bd3b9cc326a56702db30418f189"

        NOTE = "Rule was tested on VT. There is difference in the lnk.cmd_line_args and lnk.command_line_arguments mentioned in the official YARA docs. Please make modifications accordingly"

    condition:
        lnk.local_base_path == "C:\\Windows\\System32\\cmd.exe"
        and lnk.cmd_line_args contains "curl"
        and lnk.cmd_line_args contains "https://"
        and lnk.cmd_line_args contains "mshta"
        and lnk.cmd_line_args contains "hta"
        and filesize < 25KB

}